import asyncio
import json
import os
import socket
import ssl
from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from backend.src.logger import get_logger
from shared.crypto_params import AES_KEY_BYTES, AES_NONCE_BYTES
from shared.utils import encode_frame, decode_frames

log = get_logger("server")


def encode_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def decode_frames(buf: bytearray, max_size: int = 256 * 1024) -> list[bytes]:
    frames = []
    while len(buf) >= 4:
        ln = int.from_bytes(buf[:4], "big")
        if ln > max_size:
            log.error("Frame too large (%d bytes), clearing buffer", ln)
            buf.clear()
            break
        if len(buf) < 4 + ln:
            break
        frames.append(bytes(buf[4:4 + ln]))
        del buf[: 4 + ln]
    return frames


def control_msg(msg_type: str, data: dict) -> bytes:
    return json.dumps({"type": msg_type, "data": data}).encode()


def parse_control_msg(payload: bytes) -> tuple[str, dict]:
    try:
        obj = json.loads(payload.decode())
        return obj.get("type"), obj.get("data", {})
    except Exception:
        return None, {}


def enable_keepalive(sock: socket.socket):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        pass
    except Exception:
        pass


TCP_INIT = 0
TCP_READY = 1
TCP_DATA = 2
TCP_CLOSE = 3
TCP_ERR = 4


def _maybe_tls():
    return ssl.create_default_context() if os.environ.get("USE_TLS") == "1" else None


def load_key(path: str) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = f.read()
        if len(key) == AES_KEY_BYTES:
            return key
        log.warning("Shared key %s had incorrect length (%d bytes); regenerating", path, len(key))
    dir_name = os.path.dirname(os.path.abspath(path))
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    key = os.urandom(AES_KEY_BYTES)
    with open(path, "wb") as f:
        f.write(key)
    log.warning("!!! NEW SHARED KEY GENERATED: %s !!!", path)
    log.warning("IMPORTANT: YOU MUST COPY THIS FILE TO ALL MACHINES.")
    return key


class AESTunnel:
    def __init__(self, key: bytes):
        if len(key) != AES_KEY_BYTES:
            raise ValueError("Key must be %d bytes" % AES_KEY_BYTES)
        self.key = key
        self.aes = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(AES_NONCE_BYTES)
        ciphertext = self.aes.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        if len(blob) < AES_NONCE_BYTES + 1:
            raise ValueError("Blob too short")
        nonce = blob[:AES_NONCE_BYTES]
        ciphertext = blob[AES_NONCE_BYTES:]
        return self.aes.decrypt(nonce, ciphertext, None)


class ClientTCPConnection:
    def __init__(self, cid: bytes, client: "Client"):
        self.cid = cid
        self.client = client
        self.recv_q: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
        self.established = asyncio.Event()
        self.closed = asyncio.Event()

    async def send(self, data: bytes):
        if not self.closed.is_set():
            await self.client.send_tcp_data(self.cid, data)

    async def recv(self) -> bytes:
        if self.closed.is_set() and self.recv_q.empty():
            return b""
        data = await self.recv_q.get()
        return data if data is not None else b""

    async def close(self):
        if not self.closed.is_set():
            await self.client.send_tcp_close(self.cid)
        self.closed.set()
        self.recv_q.put_nowait(None)

class Client:
    def __init__(self, key: bytes | None, relay_host: str, relay_port: int):
        self.initial_key = key
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.tunnel = None
        self._writer = None
        self._reader = None
        self._writer_lock = asyncio.Lock()
        self._conn_lock = asyncio.Lock()
        self._read_task = None
        self._tcp_conns: Dict[bytes, ClientTCPConnection] = {}
        self._dns_futures: Dict[int, asyncio.Future] = {}
        self._dns_tag_counter = 0
        self._heartbeat_task = None

    def is_connected(self) -> bool:
        return (self._writer is not None and 
                self._reader is not None and 
                not self._reader.at_eof() and
                self._read_task is not None and 
                not self._read_task.done())

    async def connect(self):
        async with self._conn_lock:
            if self.is_connected(): 
                return
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.relay_host, self.relay_port, ssl=_maybe_tls()),
                    timeout=10
                )
                
                # Enable TCP keepalive
                sock = writer.get_extra_info('socket')
                if sock:
                    enable_keepalive(sock)
                    # Also disable Nagle's algorithm for lower latency
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    
            except Exception as e:
                log.error("Failed to connect to relay: %s", e)
                raise
            
            self._reader, self._writer = reader, writer
            
            # Initialize tunnel with key
            if not self.initial_key:
                raise ValueError("Client requires a shared key")
            self.tunnel = AESTunnel(self.initial_key)
            
            # Send hello
            async with self._writer_lock:
                writer.write(encode_frame(control_msg("hello", {"role": "client"})))
                await writer.drain()
            
            self._read_task = asyncio.create_task(self._read_loop())
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            log.info("Client connected to relay at %s:%s", self.relay_host, self.relay_port)

    async def _heartbeat_loop(self):
        """Send periodic heartbeat to keep connection alive."""
        try:
            while True:
                await asyncio.sleep(20)  # More relaxed (20s)
                if self.is_connected():
                    try:
                        # Send a small encrypted ping message
                        async with self._writer_lock:
                            self._writer.write(encode_frame(
                                self.tunnel.encrypt(b"PING")
                            ))
                            await self._writer.drain()
                        log.debug("Heartbeat sent")
                    except Exception as e:
                        log.error("Heartbeat failed: %s", e)
                        break
        except asyncio.CancelledError:
            pass

    async def _read_loop(self):
        buf = bytearray()
        try:
            while True:
                try:
                    data = await asyncio.wait_for(self._reader.read(4096), timeout=300) # Wait 5 mins
                except asyncio.TimeoutError:
                    continue # Just keep trying
                    
                if not data: 
                    log.warning("Client connection closed by relay")
                    break
                    
                buf.extend(data)
                for f in decode_frames(buf):
                    try:
                        msg = self.tunnel.decrypt(f)
                    except Exception as e:
                        log.error("Client decrypt failed (len=%d, key_prefix=%s, nonce=%s, tag_failure=%s): %s", 
                                 len(f), self.initial_key[:4].hex() if self.initial_key else "None",
                                 f[:12].hex(), "likely" if len(f) >= 28 else "no", e)
                        continue
                    
                    # Ignore heartbeat responses
                    if msg == b"PONG":
                        log.debug("Heartbeat response received")
                        continue
                    
                    if msg.startswith(b"DNS"):
                        tag = int.from_bytes(msg[3:5], "big")
                        fut = self._dns_futures.pop(tag, None)
                        if fut and not fut.done(): 
                            fut.set_result(msg[5:])
                    elif msg.startswith(b"TCP"):
                        opcode, cid, payload = msg[3], msg[4:8], msg[8:]
                        conn = self._tcp_conns.get(cid)
                        if not conn: 
                            continue
                        if opcode == TCP_READY: 
                            conn.established.set()
                        elif opcode == TCP_DATA: 
                            await conn.recv_q.put(payload)
                        elif opcode in (TCP_CLOSE, TCP_ERR):
                            conn.closed.set()
                            await conn.recv_q.put(None)
                            self._tcp_conns.pop(cid, None)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError) as e:
            # Catching OSError for WinError 64/121
            log.info("Client session ended: %s", str(e) or e.__class__.__name__)
        except Exception as e: 
            log.error("Client read loop error: %s", e)
        finally: 
            await self._cleanup()

    async def _cleanup(self):
        # Stop heartbeat
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None
        
        if self._writer:
            try: 
                self._writer.close()
                await self._writer.wait_closed()
            except Exception: 
                pass
        self._writer = self._reader = None
        
        # Fail all pending operations
        for fut in list(self._dns_futures.values()):
            if not fut.done():
                fut.set_exception(ConnectionError("Client disconnected"))
        self._dns_futures.clear()
        
        for conn in list(self._tcp_conns.values()):
            conn.closed.set()
            await conn.recv_q.put(None)
        self._tcp_conns.clear()
        log.info("Client cleaned up")

    async def close(self): 
        await self._cleanup()

    async def run_dns_query(self, qdata: bytes) -> bytes:
        if not self.is_connected(): 
            await self.connect()
        
        self._dns_tag_counter = (self._dns_tag_counter + 1) % 65536
        tag = self._dns_tag_counter
        fut = asyncio.get_running_loop().create_future()
        self._dns_futures[tag] = fut
        
        try:
            async with self._writer_lock:
                self._writer.write(encode_frame(
                    self.tunnel.encrypt(b"DNS" + tag.to_bytes(2, "big") + qdata)
                ))
                await self._writer.drain()
            return await asyncio.wait_for(fut, timeout=5)
        except Exception as e:
            self._dns_futures.pop(tag, None)
            log.error("DNS query failed: %s", e)
            raise

    async def open_tcp(self, host: str, port: int) -> ClientTCPConnection:
        if not self.is_connected(): 
            await self.connect()
        
        cid = os.urandom(4)
        conn = ClientTCPConnection(cid, self)
        self._tcp_conns[cid] = conn
        
        try:
            host_b = host.encode()
            payload = bytes([len(host_b)]) + host_b + port.to_bytes(2, "big")
            async with self._writer_lock:
                self._writer.write(encode_frame(
                    self.tunnel.encrypt(b"TCP" + bytes([TCP_INIT]) + cid + payload)
                ))
                await self._writer.drain()
            
            await asyncio.wait_for(conn.established.wait(), timeout=120) # 2 minute timeout
            if conn.closed.is_set(): 
                raise ConnectionError("TCP connection failed to establish")
            
            log.info("TCP connection established to %s:%s", host, port)
            return conn
        except asyncio.TimeoutError:
            self._tcp_conns.pop(cid, None)
            log.error("Edge took too long to respond (>120s)")
            raise ConnectionError("Edge response timeout")
        except Exception as e:
            self._tcp_conns.pop(cid, None)
            log.error("TCP open failed: %s", e)
            raise

    async def send_tcp_data(self, cid: bytes, data: bytes):
        if self.is_connected():
            try:
                async with self._writer_lock:
                    self._writer.write(encode_frame(
                        self.tunnel.encrypt(b"TCP" + bytes([TCP_DATA]) + cid + data)
                    ))
                    await self._writer.drain()
            except Exception as e:
                log.error("Failed to send TCP data: %s", e)

    async def send_tcp_close(self, cid: bytes):
        if self.is_connected():
            try:
                async with self._writer_lock:
                    self._writer.write(encode_frame(
                        self.tunnel.encrypt(b"TCP" + bytes([TCP_CLOSE]) + cid)
                    ))
                    await self._writer.drain()
            except Exception: 
                pass
            self._tcp_conns.pop(cid, None)

class Relay:
    def __init__(self, key: bytes, host: str, port: int):
        self.host, self.port = host, port
        self.key = key
        self.edge_queue = None
        self.active_client = None
        self.active_client_id = None
        self.client_queues = {}
        self._client_id_counter = 0

    async def start(self):
        server = await asyncio.start_server(
            self._handle_conn, host=self.host, port=self.port
        )
        log.info("Relay listening on %s:%s", self.host, self.port)
        async with server: 
            await server.serve_forever()

    async def _writer_task(self, writer, queue, name):
        try:
            while True:
                data = await queue.get()
                if data is None: 
                    break
                try:
                    writer.write(data)
                    await writer.drain()
                except Exception as e:
                    log.error("Writer task error for %s: %s", name, e)
                    break
                queue.task_done()
        finally:
            try: 
                writer.close()
                await writer.wait_closed()
            except Exception: 
                pass

    async def _handle_conn(self, reader, writer):
        peer = writer.get_extra_info("peername")
        
        # Enable keepalive on relay connections
        sock = writer.get_extra_info('socket')
        if sock:
            enable_keepalive(sock)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        buf = bytearray()
        
        try:
            # Read hello frame
            while True:
                chunk = await reader.read(4096)
                if not chunk: 
                    return
                buf.extend(chunk)
                frames = decode_frames(buf)
                if frames: 
                    hello_frame, pending_frames = frames[0], frames[1:]
                    break
            
            msg_type, data = parse_control_msg(hello_frame)
            if msg_type != "hello" or "role" not in data: 
                writer.close()
                return
            
            role = data["role"]
            log.info("Relay: %s connected from %s", role, peer)
            
            queue = asyncio.Queue()
            w_task = asyncio.create_task(self._writer_task(writer, queue, role))
            
            if role == "client":
                self._client_id_counter += 1
                client_id = self._client_id_counter
                
                # Don't kill old client immediately, just replace internal reference
                if self.active_client and self.active_client != writer:
                    log.info("Relay: New client connection, updating active client")
                
                self.active_client = writer
                self.active_client_id = client_id
                self.client_queues[writer] = queue
                
                # Drain edge queue
                if self.edge_queue:
                    count = 0
                    while not self.edge_queue.empty():
                        try:
                            self.edge_queue.get_nowait()
                            count += 1
                        except asyncio.QueueEmpty:
                            break
                    if count > 0:
                        log.info("Relay: Drained %d stale packets from edge queue", count)
                    
                    # Forward hello to edge
                    self.edge_queue.put_nowait(encode_frame(hello_frame))
                    log.info("Relay: Forwarded client %d hello to edge", client_id)
            
            elif role == "edge":
                self.edge_queue = queue
            
            # Process any frames that came with hello
            initial_data = bytearray()
            for f in pending_frames: 
                initial_data.extend(encode_frame(f))
            initial_data.extend(buf)
            
            # Start pumping data
            if role == "edge":
                await self._pump(reader, writer, True, initial_data)
                self.edge_queue = None
            elif role == "client":
                await self._pump(reader, writer, False, initial_data, client_id)
                self.client_queues.pop(writer, None)
                if self.active_client == writer: 
                    self.active_client = None
                    self.active_client_id = None
            
            queue.put_nowait(None)
            await w_task
            
        except Exception as e: 
            log.exception("Relay connection error from %s: %s", peer, e)
        finally:
            try: 
                writer.close()
            except Exception: 
                pass

    async def _pump(self, reader, writer, from_edge, initial_data, client_id=None):
        buf = bytearray()
        if initial_data:
            buf.extend(initial_data)

        async def forward_frames():
            frames = decode_frames(buf)
            for f in frames:
                data = encode_frame(f)
                if from_edge:
                    # Edge -> ONLY the active client
                    if self.active_client and self.active_client in self.client_queues:
                        try:
                            self.client_queues[self.active_client].put_nowait(data)
                        except Exception:
                            pass
                else:
                    # Client -> edge (only if this is the active client)
                    if self.active_client_id != client_id:
                        return False # Stop pumping
                    if self.edge_queue:
                        try:
                            self.edge_queue.put_nowait(data)
                        except Exception:
                            pass
            return True

        if len(buf) > 0:
            if not await forward_frames():
                return

        while True:
            # Check if this client pump should stop
            if not from_edge and client_id is not None and self.active_client_id != client_id:
                log.info("Relay: Client %d pump stopping (no longer active)", client_id)
                break

            try:
                chunk = await reader.read(4096)
                if not chunk: 
                    break
                
                buf.extend(chunk)
                if not await forward_frames():
                    break
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError) as e:
                log.info("Relay pump ended: %s", str(e) or e.__class__.__name__)
                break
            except Exception as e:
                log.error("Relay pump error: %s", e)
                break

class Edge:
    def __init__(self, key: bytes, relay_host: str, relay_port: int, upstream_dns="1.1.1.1"):
        self.key = key
        self.tunnel = None
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.upstream_dns = upstream_dns
        self.writer = None
        self._writer_lock = asyncio.Lock()
        self._tcp_conns = {}

    async def start(self):
        while True:
            try: 
                await self._run_once()
            except Exception as e: 
                log.exception("Edge error: %s", e)
            await asyncio.sleep(2)

    async def _run_once(self):
        reader, writer = await asyncio.open_connection(self.relay_host, self.relay_port)
        
        # Enable keepalive on edge connection
        sock = writer.get_extra_info('socket')
        if sock:
            enable_keepalive(sock)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        self.writer = writer
        self.tunnel = AESTunnel(self.key)
        
        async with self._writer_lock:
            writer.write(encode_frame(control_msg("hello", {"role": "edge"})))
            await writer.drain()
        
        log.info("Edge connected to relay at %s:%s", self.relay_host, self.relay_port)
        
        buf = bytearray()
        try:
            while True:
                data = await reader.read(4096)
                if not data: 
                    log.info("Edge: connection closed by relay")
                    break
                
                buf.extend(data)
                for f in decode_frames(buf):
                    # Check if it's a control message (new client hello)
                    m_type, d_dict = parse_control_msg(f)
                    if m_type == "hello":
                        log.info("Edge: New client session acknowledged")
                        # No longer resetting tunnel or clearing buffer
                        # Random nonces + shared key = stateless persistence
                        await self._close_all_tcp()
                        continue
                    
                    # Decrypt and handle message
                    try:
                        msg = self.tunnel.decrypt(f)
                    except Exception as e:
                        log.error("Edge decrypt failed (len=%d, key_prefix=%s, nonce=%s): %s", 
                                 len(f), self.key[:4].hex(), f[:12].hex(), e)
                        continue
                    
                    # Ignore heartbeat pings
                    if msg == b"PING":
                        log.debug("Heartbeat received, sending PONG")
                        async with self._writer_lock:
                            self.writer.write(encode_frame(self.tunnel.encrypt(b"PONG")))
                            await self.writer.drain()
                        continue
                    
                    if msg.startswith(b"DNS"):
                        asyncio.create_task(self._handle_dns(msg[3:5], msg[5:]))
                    elif msg.startswith(b"TCP"):
                        opcode, cid, payload = msg[3], msg[4:8], msg[8:]
                        if opcode == TCP_INIT:
                            asyncio.create_task(self._tcp_init(cid, payload))
                        elif opcode == TCP_DATA and cid in self._tcp_conns:
                            c = self._tcp_conns[cid]
                            try:
                                c["w"].write(payload)
                                await c["w"].drain()
                            except Exception as e:
                                log.error("Edge TCP write error: %s", e)
                                await self._close_tcp(cid)
                        elif opcode in (TCP_CLOSE, TCP_ERR):
                            await self._close_tcp(cid)
        finally:
            await self._close_all_tcp()
            writer.close()
            await writer.wait_closed()

    async def _handle_dns(self, tag, q):
        try:
            resp = await self._resolve_dns(q)
            if self.writer:
                async with self._writer_lock:
                    self.writer.write(encode_frame(
                        self.tunnel.encrypt(b"DNS" + tag + resp)
                    ))
                    await self.writer.drain()
        except Exception as e:
            log.error("DNS resolution failed: %s", e)

    async def _resolve_dns(self, qdata):
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        
        class P(asyncio.DatagramProtocol):
            def connection_made(self, t): 
                t.sendto(qdata)
            def datagram_received(self, d, a): 
                if not fut.done(): 
                    fut.set_result(d)
            def error_received(self, e): 
                if not fut.done(): 
                    fut.set_result(b"")
        
        t, _ = await loop.create_datagram_endpoint(
            lambda: P(), remote_addr=(self.upstream_dns, 53)
        )
        try: 
            return await asyncio.wait_for(fut, 5)
        except Exception: 
            return b""
        finally: 
            t.close()

    async def _tcp_init(self, cid, payload):
        try:
            h_len = payload[0]
            host = payload[1:1+h_len].decode()
            port = int.from_bytes(payload[1+h_len:3+h_len], "big")
            
            log.info("Edge: Opening TCP to %s:%s", host, port)
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 30)
            
            # Enable keepalive on outbound connections too
            sock = w.get_extra_info('socket')
            if sock:
                enable_keepalive(sock)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            if self.writer:
                async with self._writer_lock:
                    self.writer.write(encode_frame(
                        self.tunnel.encrypt(b"TCP" + bytes([TCP_READY]) + cid)
                    ))
                    await self.writer.drain()
            
            self._tcp_conns[cid] = {"r": r, "w": w}
            
            async def pipe():
                try:
                    while True:
                        data = await r.read(4096)
                        if not data: 
                            break
                        if self.writer:
                            async with self._writer_lock:
                                self.writer.write(encode_frame(
                                    self.tunnel.encrypt(b"TCP" + bytes([TCP_DATA]) + cid + data)
                                ))
                                await self.writer.drain()
                except Exception as e:
                    log.error("Edge TCP pipe error: %s", e)
                finally:
                    if self.writer:
                        try:
                            async with self._writer_lock:
                                self.writer.write(encode_frame(
                                    self.tunnel.encrypt(b"TCP" + bytes([TCP_CLOSE]) + cid)
                                ))
                                await self.writer.drain()
                        except Exception:
                            pass
                    await self._close_tcp(cid)
            
            asyncio.create_task(pipe())
            
        except Exception as e:
            log.error("Edge TCP init failed: %s", e)
            if self.writer:
                try:
                    async with self._writer_lock:
                        self.writer.write(encode_frame(
                            self.tunnel.encrypt(b"TCP" + bytes([TCP_ERR]) + cid)
                        ))
                        await self.writer.drain()
                except Exception:
                    pass

    async def _close_tcp(self, cid):
        c = self._tcp_conns.pop(cid, None)
        if c:
            try: 
                c["w"].close()
                await c["w"].wait_closed()
            except Exception: 
                pass

    async def _close_all_tcp(self):
        for cid in list(self._tcp_conns.keys()): 
            await self._close_tcp(cid)

async def main():
    role = os.getenv("ROLE", "relay")
    key = load_key(os.getenv("SHARED_KEY_FILE", "shared.key"))
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8443"))
    r_host = os.getenv("RELAY_HOST", "127.0.0.1")
    r_port = int(os.getenv("RELAY_PORT", "8443"))
    
    if role == "relay": 
        await Relay(key, host, port).start()
    elif role == "edge": 
        await Edge(key, r_host, r_port, os.getenv("UPSTREAM_DNS", "1.1.1.1")).start()

if __name__ == "__main__":
    try: 
        asyncio.run(main())
    except KeyboardInterrupt: 
        pass