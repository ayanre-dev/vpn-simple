import asyncio
import json
import os
import socket
import ssl
from typing import Optional

from backend.src.logger import get_logger
from backend.src.crypto import AESTunnel  # make sure backend/src/crypto.py exists

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
    def __init__(self, cid: bytes, writer: asyncio.StreamWriter, tunnel: AESTunnel):
        self.cid = cid
        self.writer = writer
        self.tunnel = tunnel
        self.recv_q: asyncio.Queue[bytes] = asyncio.Queue()
        self.closed = asyncio.Event()
        self._reader_task: asyncio.Task | None = None

    async def send(self, data: bytes):
        if self.closed.is_set():
            return
        self.writer.write(
            encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_DATA]) + self.cid + data))
        )
        await self.writer.drain()

    async def recv(self) -> bytes:
        if self.closed.is_set() and self.recv_q.empty():
            return b""
        return await self.recv_q.get()

    async def close(self):
        if not self.closed.is_set():
            self.writer.write(
                encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_CLOSE]) + self.cid))
            )
            await self.writer.drain()
        self.closed.set()
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        if self._reader_task:
            self._reader_task.cancel()


class Client:
    def __init__(self, key: bytes, relay_host: str, relay_port: int):
        self.tunnel = AESTunnel(key)
        self.relay_host = relay_host
        self.relay_port = relay_port

    async def run_dns_query(self, qdata: bytes):
        reader, writer = await asyncio.open_connection(
            self.relay_host, self.relay_port, ssl=_maybe_tls()
        )
        writer.write(encode_frame(control_msg("hello", {"role": "client"})))
        await writer.drain()
        writer.write(encode_frame(self.tunnel.encrypt(b"DNS" + qdata)))
        await writer.drain()
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
                    except Exception:
                        continue
                    if msg.startswith(b"DNS"):
                        return msg[3:]
        finally:
            writer.close()
            await writer.wait_closed()
        return b""

    async def open_tcp(self, host: str, port: int) -> ClientTCPConnection:
        reader, writer = await asyncio.open_connection(
            self.relay_host, self.relay_port, ssl=_maybe_tls()
        )
        writer.write(encode_frame(control_msg("hello", {"role": "client"})))
        await writer.drain()

        cid = os.urandom(4)
        host_b = host.encode()
        init_payload = bytes([len(host_b)]) + host_b + port.to_bytes(2, "big")
        writer.write(
            encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_INIT]) + cid + init_payload))
        )
        await writer.drain()

        conn = ClientTCPConnection(cid, writer, self.tunnel)
        ready = asyncio.Event()

        async def reader_task():
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
                        except Exception:
                            continue
                        if not msg.startswith(b"TCP"):
                            continue
                        opcode = msg[3]
                        rcid = msg[4:8]
                        payload = msg[8:]
                        if rcid != cid:
                            continue
                        if opcode == TCP_READY:
                            ready.set()
                        elif opcode == TCP_DATA:
                            conn.recv_q.put_nowait(payload)
                        elif opcode in (TCP_CLOSE, TCP_ERR):
                            conn.closed.set()
                            ready.set()
                            return
            finally:
                conn.closed.set()

        conn._reader_task = asyncio.create_task(reader_task())

        try:
            await asyncio.wait_for(ready.wait(), timeout=15)  # was 5
        except asyncio.TimeoutError:
            await conn.close()
            raise ConnectionError("TCP open timed out")

        if conn.closed.is_set():
            await conn.close()
            raise ConnectionError("TCP open failed")

        return conn

    async def close(self):
        # stateless per-connection client; nothing persistent to close
        return


# ---------- Relay ----------

class Relay:
    """
    Simple relay: one or more clients, one edge.
    First frame must be a plaintext control hello with role.
    All subsequent payloads are framed; relay forwards frames between client(s) and edge.
    """
    def __init__(self, key: bytes, host: str, port: int):
        self.host = host
        self.port = port
        self.tunnel = AESTunnel(key)
        self.edge_writer: Optional[asyncio.StreamWriter] = None
        self.clients: set[asyncio.StreamWriter] = set()

    async def start(self):
        server = await asyncio.start_server(self._handle_conn, host=self.host, port=self.port, ssl=None)
        log.info("Relay listening on %s:%s", self.host, self.port)
        async with server:
            await server.serve_forever()

    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        buf = bytearray()
        try:
            # Expect first frame as plaintext control msg
            data = await reader.readexactly(4)
            buf.extend(data)
            frames = decode_frames(buf)
            while not frames:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                buf.extend(chunk)
                frames = decode_frames(buf)
            hello = frames[0]
            msg_type, data = parse_control_msg(hello)
            if msg_type != "hello" or "role" not in data:
                log.warning("Relay: bad hello from %s", peer)
                writer.close()
                await writer.wait_closed()
                return
            role = data["role"]
            log.info("Relay: %s connected from %s", role, peer)

            if role == "edge":
                self.edge_writer = writer
                await self._pump(reader, writer, from_edge=True)
            elif role == "client":
                self.clients.add(writer)
                await self._pump(reader, writer, from_edge=False)
            else:
                log.warning("Relay: unknown role %s from %s", role, peer)
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            log.exception("Relay conn error from %s: %s", peer, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if writer in self.clients:
                self.clients.discard(writer)
            if self.edge_writer is writer:
                self.edge_writer = None

    async def _pump(self, reader, writer, from_edge: bool):
        buf = bytearray()
        while True:
            data = await reader.read(4096)
            if not data:
                break
            buf.extend(data)
            frames = decode_frames(buf)
            for f in frames:
                if from_edge:
                    dead = []
                    for cw in self.clients:
                        try:
                            cw.write(f)        # forward raw encrypted frame
                            await cw.drain()
                        except Exception:
                            dead.append(cw)
                    for d in dead:
                        self.clients.discard(d)
                else:
                    if self.edge_writer:
                        self.edge_writer.write(f)   # forward raw encrypted frame
                        await self.edge_writer.drain()
        # end


# ---------- Edge ----------

class Edge:
    """
    Connects to relay as role=edge, handles DNS and TCP frames.
    """
    def __init__(self, key: bytes, relay_host: str, relay_port: int, upstream_dns: str = "1.1.1.1"):
        self.tunnel = AESTunnel(key)
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.upstream_dns = upstream_dns
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._tcp_conns: dict[bytes, dict] = {}

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
        writer.write(encode_frame(control_msg("hello", {"role": "edge"})))
        await writer.drain()
        log.info("Edge connected to relay %s:%s", self.relay_host, self.relay_port)

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
                    except Exception:
                        continue
                    # DNS
                    if msg.startswith(b"DNS"):
                        q = msg[3:]
                        resp = await self._handle_dns(q)
                        writer.write(encode_frame(self.tunnel.encrypt(b"DNS" + resp)))
                        await writer.drain()
                    # TCP
                    elif msg.startswith(b"TCP"):
                        opcode = msg[3]
                        cid = msg[4:8]
                        payload = msg[8:]
                        if opcode == TCP_INIT:
                            await self._handle_tcp_init(cid, payload, writer)
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

    async def _handle_dns(self, qdata: bytes) -> bytes:
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

    async def _handle_tcp_init(self, cid: bytes, payload: bytes, writer: asyncio.StreamWriter):
        try:
            host_len = payload[0]
            host = payload[1 : 1 + host_len].decode()
            port = int.from_bytes(payload[1 + host_len : 1 + host_len + 2], "big")
            log.info("Edge: TCP_INIT cid=%s %s:%s", cid.hex(), host, port)

            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port, family=socket.AF_INET),
                timeout=8,
            )
            log.info("Edge: TCP connected cid=%s %s:%s", cid.hex(), host, port)

            # Send READY back
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
                        writer.write(
                            encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_DATA]) + cid + data))
                        )
                        await writer.drain()
                finally:
                    writer.write(
                        encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_CLOSE]) + cid))
                    )
                    await writer.drain()
                    await self._close_tcp(cid)

            asyncio.create_task(up_to_client())

        except Exception as e:
            log.exception("Edge: TCP_INIT failed cid=%s %s:%s", cid.hex(), host if 'host' in locals() else '?', port if 'port' in locals() else '?')
            writer.write(encode_frame(self.tunnel.encrypt(b"TCP" + bytes([TCP_ERR]) + cid)))
            await writer.drain()

    async def _close_tcp(self, cid: bytes):
        if cid in self._tcp_conns:
            conn = self._tcp_conns.pop(cid)
            try:
                conn["writer"].close()
                await conn["writer"].wait_closed()
            except Exception:
                pass

    async def _close_all_tcp(self):
        for cid in list(self._tcp_conns.keys()):
            await self._close_tcp(cid)
        self._tcp_conns.clear()


# ---------- Entrypoint selector ----------

async def main():
    role = os.environ.get("ROLE", "client")
    key_file = os.environ.get("SHARED_KEY_FILE", "shared.key")
    relay_host = os.environ.get("RELAY_HOST", "127.0.0.1")
    relay_port = int(os.environ.get("RELAY_PORT", "8443"))
    upstream_dns = os.environ.get("UPSTREAM_DNS", "1.1.1.1")

    with open(key_file, "rb") as f:
        key = f.read()

    if role == "relay":
        srv = Relay(key, relay_host, relay_port)
        await srv.start()
    elif role == "edge":
        edge = Edge(key, relay_host, relay_port, upstream_dns=upstream_dns)
        await edge.start()
    else:
        log.error("Unknown ROLE %s", role)


if __name__ == "__main__":
    asyncio.run(main())