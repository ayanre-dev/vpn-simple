import asyncio
import json
import os
import socket
import ssl
from typing import Optional, Dict

from backend.src.logger import get_logger
from backend.src.crypto import AESTunnel  # make sure backend/src/crypto.py exists
from shared.handshake import client_handshake, edge_handshake

log = get_logger("server")

# Frame helpers (length-prefixed)
def encode_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def decode_frames(buf: bytearray) -> list[bytes]:
    frames = []
    while len(buf) >= 4:
        ln = int.from_bytes(buf[:4], "big")
        if len(buf) < 4 + ln:
            break
        frames.append(bytes(buf[4 : 4 + ln]))
        del buf[: 4 + ln]
    return frames


# Control message helpers (plaintext control frames)
def control_msg(msg_type: str, data: dict) -> bytes:
    return json.dumps({"type": msg_type, "data": data}).encode()


def parse_control_msg(payload: bytes) -> tuple[str, dict]:
    obj = json.loads(payload.decode())
    return obj.get("type"), obj.get("data", {})


# TCP opcodes
TCP_INIT = 0
TCP_READY = 1
TCP_DATA = 2
TCP_CLOSE = 3
TCP_ERR = 4


def _maybe_tls():
    return ssl.create_default_context() if os.environ.get("USE_TLS") == "1" else None


# ---------- Client-side (used by control_api) ----------

class ClientTCPConnection:
    def __init__(self, cid: bytes, client: "Client"):
        self.cid = cid
        self.client = client
        self.recv_q: asyncio.Queue[bytes] = asyncio.Queue()
        self.established = asyncio.Event()
        self.closed = asyncio.Event()

    async def send(self, data: bytes):
        if self.closed.is_set():
            return
        await self.client.send_tcp_data(self.cid, data)

    async def recv(self) -> bytes:
        if self.closed.is_set() and self.recv_q.empty():
            return b""
        data = await self.recv_q.get()
        if data is None:  # Sentinel
            return b""
        return data

    async def close(self):
        if not self.closed.is_set():
            await self.client.send_tcp_close(self.cid)
        self.closed.set()


class Client:
    def __init__(self, key: bytes | None, relay_host: str, relay_port: int):
        self.initial_key = key
        self.relay_host = relay_host
        self.relay_port = relay_port
        
        self.tunnel: AESTunnel | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer_lock = asyncio.Lock()
        
        self._read_task: asyncio.Task | None = None
        self._tcp_conns: Dict[bytes, ClientTCPConnection] = {}
        
        # DNS Multiplexing: Map 2-byte tag (int) to future
        self._dns_futures: Dict[int, asyncio.Future] = {}
        self._dns_tag_counter = 0

        # Optional server public key (Ed25519) to enable handshake
        self._edge_pubkey: bytes | None = None
        edge_pub_path = os.environ.get("EDGE_PUBKEY_FILE")
        if edge_pub_path and os.path.exists(edge_pub_path):
            with open(edge_pub_path, "rb") as f:
                pk = f.read().strip()
            if len(pk) == 32:
                self._edge_pubkey = pk
            else:
                log.warning("EDGE_PUBKEY_FILE present but not 32 bytes; ignoring")

    async def connect(self):
        """Establish persistent connection to relay."""
        if self._writer:
            return  # Already connected

        reader, writer = await asyncio.open_connection(
            self.relay_host, self.relay_port, ssl=_maybe_tls()
        )
        async with self._writer_lock:
            writer.write(encode_frame(control_msg("hello", {"role": "client"})))
            await writer.drain()

        # Handshake
        if self._edge_pubkey is not None:
            session_key = await client_handshake(reader, writer, self._edge_pubkey)
            self.tunnel = AESTunnel(session_key)
        elif self.initial_key is not None:
             self.tunnel = AESTunnel(self.initial_key)
        else:
             writer.close()
             await writer.wait_closed()
             raise RuntimeError("No handshake configured and no pre-shared key provided")

        self._reader = reader
        self._writer = writer
        self._read_task = asyncio.create_task(self._read_loop())
        log.info("Client connected to relay")

    async def _read_loop(self):
        buf = bytearray()
        try:
            while True:
                data = await self._reader.read(4096)
                if not data:
                    break
                buf.extend(data)
                frames = decode_frames(buf)
                for f in frames:
                    try:
                        msg = self.tunnel.decrypt(f)
                    except Exception as e:
                        log.error("Client decrypt failed (len=%d, start=%s): %s", len(f), f[:16].hex(), e)
                        continue
                    
                    if msg.startswith(b"DNS"):
                        if len(msg) >= 5:
                            tag = int.from_bytes(msg[3:5], "big")
                            payload = msg[5:]
                            fut = self._dns_futures.pop(tag, None)
                            if fut and not fut.done():
                                fut.set_result(payload)
                    
                    elif msg.startswith(b"TCP"):
                        opcode = msg[3]
                        cid = msg[4:8]
                        payload = msg[8:]
                        conn = self._tcp_conns.get(cid)
                        
                        if not conn:
                            # delayed packet for closed conn?
                            continue
                            
                        if opcode == TCP_READY:
                            if conn:
                                conn.established.set()
                        elif opcode == TCP_DATA:
                            conn.recv_q.put_nowait(payload)
                        elif opcode in (TCP_CLOSE, TCP_ERR):
                            conn.established.set() # Wake up any waiters
                            conn.closed.set()
                            conn.recv_q.put_nowait(None)
                            self._tcp_conns.pop(cid, None)

        except Exception as e:
            log.error("Client read loop error: %s", e)
        finally:
            log.info("Client read loop ended")
            await self._cleanup()

    async def _cleanup(self):
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._writer = None
        self._reader = None
        # close all tcp conns
        for conn in self._tcp_conns.values():
            conn.closed.set()
            conn.recv_q.put_nowait(None)
        self._tcp_conns.clear()
        # cancel pending dns
        for fut in self._dns_futures.values():
            if not fut.done():
                fut.cancel()
        self._dns_futures.clear()

    async def run_dns_query(self, qdata: bytes) -> bytes:
        if not self._writer:
            await self.connect()
        
        start_ts = asyncio.get_running_loop().time()
        
        # Use simple counter-based tag for 2-byte space (0-65535)
        self._dns_tag_counter = (self._dns_tag_counter + 1) % 65536
        tag = self._dns_tag_counter
        tag_bytes = tag.to_bytes(2, "big")
        
        fut = asyncio.get_running_loop().create_future()
        self._dns_futures[tag] = fut
        
        try:
            async with self._writer_lock:
                self._writer.write(encode_frame(self.tunnel.encrypt(b"DNS" + tag_bytes + qdata)))
                await self._writer.drain()
            res = await asyncio.wait_for(fut, timeout=5)
            dur = asyncio.get_running_loop().time() - start_ts
            log.info("Client: DNS query (tag=%d) took %.3fs", tag, dur)
            return res
        except Exception as e:
            self._dns_futures.pop(tag, None)
            dur = asyncio.get_running_loop().time() - start_ts
            log.warning("Client: DNS query (tag=%d) failed after %.3fs: %s", tag, dur, e)
            raise

    async def open_tcp(self, host: str, port: int) -> ClientTCPConnection:
        if not self._writer:
            await self.connect()

        cid = os.urandom(4)
        host_b = host.encode()
        init_payload = bytes([len(host_b)]) + host_b + port.to_bytes(2, "big")
        
        # Register before sending to catch READY/ERR
        conn = ClientTCPConnection(cid, self)
        self._tcp_conns[cid] = conn
        
        try:
            async with self._writer_lock:
                self._writer.write(
                    encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_INIT]) + cid + init_payload))
                )
                await self._writer.drain()
        except Exception:
            self._tcp_conns.pop(cid, None)
            raise

        # Wait for READY or failure
        try:
            await asyncio.wait_for(conn.established.wait(), timeout=30)
        except asyncio.TimeoutError:
            self._tcp_conns.pop(cid, None)
            raise ConnectionError("TCP connection timed out at Edge")

        if conn.closed.is_set():
            raise ConnectionError("TCP connection failed at Edge")

        return conn

    async def send_tcp_data(self, cid: bytes, data: bytes):
        if not self._writer:
            return
        async with self._writer_lock:
            self._writer.write(
                encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_DATA]) + cid + data))
            )
            await self._writer.drain()

    async def send_tcp_close(self, cid: bytes):
        if not self._writer:
            return
        try:
            async with self._writer_lock:
                self._writer.write(
                    encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_CLOSE]) + cid))
                )
                await self._writer.drain()
        except Exception:
            pass
        self._tcp_conns.pop(cid, None)

def load_key(path: str) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(path, "wb") as f:
        f.write(key)
    log.warning("!!! NEW SHARED KEY GENERATED: %s !!!", path)
    log.warning("IMPORTANT: If you are running multiple PCs, YOU MUST COPY THIS FILE TO ALL MACHINES.")
    return key

class Relay:
    """
    Simple relay: one or more clients, one edge.
    First frame must be a plaintext control hello with role.
    All subsequent payloads are framed; relay forwards frames between client(s) and edge.
    Uses per-client queues to guarantee packet ordering without head-of-line blocking.
    """
    def __init__(self, key: bytes, host: str, port: int):
        self.host = host
        self.port = port
        self.tunnel = AESTunnel(key)
        self.edge_queue: Optional[asyncio.Queue] = None
        self.clients: dict[asyncio.StreamWriter, asyncio.Queue] = {}

    async def start(self):
        server = await asyncio.start_server(self._handle_conn, host=self.host, port=self.port, ssl=None)
        log.info("Relay listening on %s:%s", self.host, self.port)
        async with server:
            await server.serve_forever()

    async def _writer_task(self, writer: asyncio.StreamWriter, queue: asyncio.Queue, name: str):
        """Dedicated task to pull from queue and write to socket to preserve order."""
        try:
            while True:
                data = await queue.get()
                if data is None: break
                writer.write(data)
                await writer.drain()
                queue.task_done()
        except Exception as e:
            log.warning("Relay: writer task for %s failed: %s", name, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception: pass

    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        buf = bytearray()
        try:
            # Expect first frame as plaintext control msg
            while True:
                chunk = await reader.read(4096)
                if not chunk: return
                buf.extend(chunk)
                frames = decode_frames(buf)
                if frames:
                    hello_frame = frames[0]
                    pending_frames = frames[1:]
                    break
            
            msg_type, data = parse_control_msg(hello_frame)
            if msg_type != "hello" or "role" not in data:
                log.warning("Relay: bad hello from %s", peer)
                writer.close()
                return
            role = data["role"]
            log.info("Relay: %s connected from %s", role, peer)

            queue = asyncio.Queue(maxsize=1000)
            writer_task = asyncio.create_task(self._writer_task(writer, queue, f"{role}@{peer}"))

            # Re-assemble initial data: any trailing bytes in buf + pending frames
            initial_data = bytearray()
            for f in pending_frames:
                initial_data.extend(encode_frame(f))
            initial_data.extend(buf)

            if role == "edge":
                self.edge_queue = queue
                await self._pump(reader, writer, from_edge=True, initial_buf=initial_data)
                self.edge_queue = None
            elif role == "client":
                self.clients[writer] = queue
                await self._pump(reader, writer, from_edge=False, initial_buf=initial_data)
                self.clients.pop(writer, None)
            else:
                log.warning("Relay: unknown role %s from %s", role, peer)

            # Signal writer task to stop
            queue.put_nowait(None)
            await writer_task

        except Exception as e:
            log.exception("Relay conn error from %s: %s", peer, e)
        finally:
            try:
                writer.close()
            except Exception: pass

    async def _pump(self, reader, writer, from_edge: bool, initial_buf: bytearray = None):
        """Pass-through pump. Ordered writes are handled by the _writer_task."""
        
        async def forward(data):
            if from_edge:
                for cw, q in list(self.clients.items()):
                    try:
                        q.put_nowait(data)
                    except asyncio.QueueFull:
                        log.warning("Relay: client queue full, dropping packet")
            else:
                if self.edge_queue:
                    try:
                        self.edge_queue.put_nowait(data)
                    except asyncio.QueueFull:
                        log.warning("Relay: edge queue full, dropping packet")
                else:
                    log.warning("Relay: dropping client packet, Edge NOT connected")

        if initial_buf and len(initial_buf) > 0:
            await forward(initial_buf)

        while True:
            data = await reader.read(4096)
            if not data:
                break
            await forward(data)
        # end


# ---------- Edge ----------

class Edge:
    """
    Connects to relay as role=edge, handles DNS and TCP frames.
    """
    def __init__(self, key: bytes, relay_host: str, relay_port: int, upstream_dns: str = "1.1.1.1"):
        # Default PSK tunnel (fallback)
        self.tunnel = AESTunnel(key)
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.upstream_dns = upstream_dns
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._writer_lock = asyncio.Lock()
        self._tcp_conns: dict[bytes, dict] = {}
        # Optional edge static key for handshake (Ed25519 private key, 32 bytes)
        self._edge_sk: bytes | None = None
        edge_sk_path = os.environ.get("EDGE_SK_FILE")
        if edge_sk_path and os.path.exists(edge_sk_path):
            with open(edge_sk_path, "rb") as f:
                sk = f.read().strip()
            if len(sk) == 32:
                self._edge_sk = sk
            else:
                log.warning("EDGE_SK_FILE present but not 32 bytes; ignoring")

    async def start(self):
        while True:
            try:
                await self._run_once()
            except Exception as e:
                log.exception("Edge loop error: %s", e)
            await asyncio.sleep(1)

    async def _run_once(self):
        reader, writer = await asyncio.open_connection(
            self.relay_host, self.relay_port, ssl=_maybe_tls()
        )
        self.reader, self.writer = reader, writer
        async with self._writer_lock:
            writer.write(encode_frame(control_msg("hello", {"role": "edge"})))
            await writer.drain()
        log.info("Edge connected to relay %s:%s", self.relay_host, self.relay_port)

        # If handshake is enabled, run it to derive session tunnel
        if self._edge_sk is not None:
             # handshake handles its own writer usage inside its internal loop, 
             # but here we are calling it before the main reader loop starts.
            session_key = await edge_handshake(reader, writer, self._edge_sk)
            self.tunnel = AESTunnel(session_key)

        buf = bytearray()
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                buf.extend(data)
                frames = decode_frames(buf)
                for f in frames:
                    try:
                        msg = self.tunnel.decrypt(f)
                    except Exception as e:
                        log.error("Edge decrypt failed (len=%d, start=%s): %s", len(f), f[:16].hex(), e)
                        continue
                    # DNS
                    if msg.startswith(b"DNS"):
                        if len(msg) >= 5:
                            tag_bytes = msg[3:5]
                            q = msg[5:]
                            # Process DNS in background to avoid blocking TCP traffic
                            asyncio.create_task(self._handle_dns_bg(tag_bytes, q))
                        else:
                            log.error("Edge: malformed DNS frame (no tag)")
                    # TCP
                    elif msg.startswith(b"TCP"):
                        opcode = msg[3]
                        cid = msg[4:8]
                        payload = msg[8:]
                        if opcode == TCP_INIT:
                            # Start TCP handling in background (it uses asyncio.open_connection)
                            asyncio.create_task(self._handle_tcp_init(cid, payload))
                        elif opcode == TCP_DATA:
                            conn = self._tcp_conns.get(cid)
                            if conn:
                                conn["writer"].write(payload)
                                await conn["writer"].drain()
                        elif opcode in (TCP_CLOSE, TCP_ERR):
                            await self._close_tcp(cid)
        finally:
            await self._close_all_tcp()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            log.info("Edge disconnected from relay")

    async def _handle_dns_bg(self, tag_bytes: bytes, qdata: bytes):
        """Handle DNS query in background and write response back to tunnel."""
        try:
            resp = await self._resolve_dns(qdata)
            if self.writer and not self.writer.is_closing():
                async with self._writer_lock:
                    self.writer.write(encode_frame(self.tunnel.encrypt(b"DNS" + tag_bytes + resp)))
                    await self.writer.drain()
        except Exception as e:
            log.warning("Edge: DNS error: %s", e)

    async def _resolve_dns(self, qdata: bytes) -> bytes:
        # minimal UDP DNS forwarder
        loop = asyncio.get_running_loop()
        on_response = loop.create_future()

        def protocol_factory():
            class DNSProto(asyncio.DatagramProtocol):
                def connection_made(self, transport):
                    self.transport = transport
                    transport.sendto(qdata)

                def datagram_received(self, data, addr):
                    if not on_response.done():
                        on_response.set_result(data)

                def error_received(self, exc):
                    if not on_response.done():
                        on_response.set_result(b"")

            return DNSProto()

        transport, _ = await loop.create_datagram_endpoint(
            protocol_factory, remote_addr=(self.upstream_dns, 53)
        )
        try:
            return await asyncio.wait_for(on_response, timeout=5)
        except asyncio.TimeoutError:
            return b""
        finally:
            transport.close()

    async def _handle_tcp_init(self, cid: bytes, payload: bytes):
        # Note: self.writer could change if Edge reconnects, but for a single session it's stable.
        # We capture 'writer' from the loop scope or check self.writer.
        writer = self.writer
        if not writer: 
            return

        try:
            host_len = payload[0]
            host = payload[1 : 1 + host_len].decode()
            port = int.from_bytes(payload[1 + host_len : 1 + host_len + 2], "big")
            log.info("Edge: TCP_INIT cid=%s %s:%s", cid.hex(), host, port)

            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port, family=socket.AF_INET),
                timeout=30,
            )
            log.info("Edge: TCP connected cid=%s %s:%s", cid.hex(), host, port)

            # Send READY back
            async with self._writer_lock:
                writer.write(encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_READY]) + cid)))
                await writer.drain()

            self._tcp_conns[cid] = {
                "reader": upstream_reader,
                "writer": upstream_writer,
            }

            async def up_to_client():
                try:
                    while True:
                        data = await upstream_reader.read(4096)
                        if not data:
                            break
                        # Use self.writer again, hoping it's still valid
                        if self.writer and not self.writer.is_closing():
                            async with self._writer_lock:
                                self.writer.write(
                                    encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_DATA]) + cid + data))
                                )
                                await self.writer.drain()
                        else:
                            break
                except Exception as e:
                    log.warning("Edge: up_to_client error cid=%s: %s", cid.hex(), e)
                finally:
                    try:
                        if self.writer and not self.writer.is_closing():
                            async with self._writer_lock:
                                self.writer.write(
                                    encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_CLOSE]) + cid))
                                )
                                await self.writer.drain()
                    except Exception:
                        pass
                    await self._close_tcp(cid)

            asyncio.create_task(up_to_client())

        except Exception as e:
            log.exception("Edge: TCP_INIT failed cid=%s %s:%s", cid.hex(), host if 'host' in locals() else '?', port if 'port' in locals() else '?')
            try:
                if self.writer and not self.writer.is_closing():
                    async with self._writer_lock:
                        writer.write(encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_ERR]) + cid)))
                        await writer.drain()
            except Exception:
                pass

    async def _close_tcp(self, cid: bytes):
        if cid in self._tcp_conns:
            conn = self._tcp_conns.pop(cid)
            try:
                conn["writer"].close()
                await conn["writer"].wait_closed()
            except Exception as e:
                log.debug("Edge: _close_tcp error cid=%s: %s", cid.hex(), e)

    async def _close_all_tcp(self):
        for cid in list(self._tcp_conns.keys()):
            await self._close_tcp(cid)
        self._tcp_conns.clear()


# ---------- Entrypoint selector ----------

async def main():
    role = os.environ.get("ROLE", "relay")
    key_file = os.environ.get("SHARED_KEY_FILE", "shared.key")
    relay_host = os.environ.get("RELAY_HOST", "127.0.0.1")
    relay_port = int(os.environ.get("RELAY_PORT", "8443"))
    
    # For binding the server (Relay)
    bind_host = os.environ.get("HOST", "0.0.0.0")
    bind_port = int(os.environ.get("PORT", "8443"))
    
    upstream_dns = os.environ.get("UPSTREAM_DNS", "1.1.1.1")

    with open(key_file, "rb") as f:
        key = f.read()

    if role == "relay":
        # Relay binds to HOST:PORT (e.g. 0.0.0.0:8443)
        srv = Relay(key, bind_host, bind_port)
        await srv.start()
    elif role == "edge":
        edge = Edge(key, relay_host, relay_port, upstream_dns=upstream_dns)
        await edge.start()
    else:
        log.error("Unknown ROLE %s", role)
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())