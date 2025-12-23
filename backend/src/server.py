import asyncio
import json
import os
import socket
import ssl
from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from backend.src.logger import get_logger

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

def control_msg(msg_type: str, data: dict) -> bytes:
    return json.dumps({"type": msg_type, "data": data}).encode()

def parse_control_msg(payload: bytes) -> tuple[str, dict]:
    try:
        obj = json.loads(payload.decode())
        return obj.get("type"), obj.get("data", {})
    except Exception:
        return None, {}

# TCP opcodes
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
            return f.read()
    dir_name = os.path.dirname(os.path.abspath(path))
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    key = os.urandom(32)
    with open(path, "wb") as f:
        f.write(key)
    log.warning("!!! NEW SHARED KEY GENERATED: %s !!!", path)
    log.warning("IMPORTANT: YOU MUST COPY THIS FILE TO ALL MACHINES.")
    return key

class AESTunnel:
    """
    FIXED: Uses random nonces prepended to ciphertext instead of sequential counters.
    This prevents nonce desynchronization issues.
    """
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        self.key = key
        self.aes = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)  # Random nonce each time
        ciphertext = self.aes.encrypt(nonce, plaintext, None)
        return nonce + ciphertext  # Prepend nonce to ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        if len(blob) < 13:  # 12-byte nonce + at least 1 byte ciphertext
            raise ValueError("Blob too short")
        nonce = blob[:12]
        ciphertext = blob[12:]
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

    def is_connected(self) -> bool:
        return self._writer is not None and self._read_task is not None and not self._read_task.done()

    async def connect(self):
        async with self._conn_lock:
            if self.is_connected(): 
                return
            
            reader, writer = await asyncio.open_connection(
                self.relay_host, self.relay_port, ssl=_maybe_tls()
            )
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
            log.info("Client connected to relay at %s:%s", self.relay_host, self.relay_port)

    async def _read_loop(self):
        buf = bytearray()
        try:
            while True:
                data = await self._reader.read(4096)
                if not data: 
                    log.warning("Client connection closed by relay")
                    break
                buf.extend(data)
                for f in decode_frames(buf):
                    try:
                        msg = self.tunnel.decrypt(f)
                    except Exception as e:
                        log.error("Client decrypt failed (len=%d): %s", len(f), e)
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
                            conn.recv_q.put_nowait(payload)
                        elif opcode in (TCP_CLOSE, TCP_ERR):
                            conn.closed.set()
                            conn.recv_q.put_nowait(None)
                            self._tcp_conns.pop(cid, None)
        except Exception as e: 
            log.error("Client read loop error: %s", e)
        finally: 
            await self._cleanup()

    async def _cleanup(self):
        if self._writer:
            try: 
                self._writer.close()
                await self._writer.wait_closed()
            except Exception: 
                pass
        self._writer = self._reader = None
        for conn in list(self._tcp_conns.values()):
            conn.closed.set()
            conn.recv_q.put_nowait(None)
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
            
            await asyncio.wait_for(conn.established.wait(), timeout=30)
            if conn.closed.is_set(): 
                raise ConnectionError("TCP connection failed to establish")
            
            log.info("TCP connection established to %s:%s", host, port)
            return conn
        except Exception as e:
            self._tcp_conns.pop(cid, None)
            log.error("Failed to open TCP to %s:%s: %s", host, port, e)
            raise

    async def send_tcp_data(self, cid: bytes, data: bytes):
        if self.is_connected():
            async with self._writer_lock:
                self._writer.write(encode_frame(
                    self.tunnel.encrypt(b"TCP" + bytes([TCP_DATA]) + cid + data)
                ))
                await self._writer.drain()

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
        self.key = key  # Store key but don't create tunnel (relay just forwards)
        self.edge_queue = None
        self.active_client = None
        self.client_queues = {}

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
                writer.write(data)
                await writer.drain()
                queue.task_done()
        finally:
            try: 
                writer.close()
                await writer.wait_closed()
            except Exception: 
                pass

    async def _handle_conn(self, reader, writer):
        peer = writer.get_extra_info("peername")
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
                # Close old client if exists
                if self.active_client in self.client_queues:
                    old_queue = self.client_queues.pop(self.active_client)
                    old_queue.put_nowait(None)
                    log.info("Relay: Disconnected previous client")
                
                self.active_client = writer
                self.client_queues[writer] = queue
                
                # Drain edge queue to prevent nonce issues
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
                    
                    # Forward hello to edge so it knows new session started
                    self.edge_queue.put_nowait(encode_frame(hello_frame))
                    log.info("Relay: Forwarded client hello to edge")
            
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
                await self._pump(reader, writer, False, initial_data)
                self.client_queues.pop(writer, None)
                if self.active_client == writer: 
                    self.active_client = None
            
            queue.put_nowait(None)
            await w_task
            
        except Exception as e: 
            log.exception("Relay connection error from %s: %s", peer, e)
        finally:
            try: 
                writer.close()
            except Exception: 
                pass

    async def _pump(self, reader, writer, from_edge, initial_buf):
        async def forward(data):
            if from_edge:
                # Edge -> all clients
                for q in list(self.client_queues.values()): 
                    q.put_nowait(data)
            else:
                # Client -> edge (only if this is the active client)
                if writer != self.active_client:
                    return  # Ignore inactive clients
                if self.edge_queue:
                    self.edge_queue.put_nowait(data)
        
        if initial_buf: 
            await forward(initial_buf)
        
        while True:
            data = await reader.read(4096)
            if not data: 
                break
            await forward(data)

class Edge:
    def __init__(self, key: bytes, relay_host: str, relay_port: int, upstream_dns="1.1.1.1"):
        self.key = key
        self.tunnel = None  # Will be created on each connection
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
        self.writer = writer
        self.tunnel = AESTunnel(self.key)  # Fresh tunnel for new session
        
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
                        log.info("Edge: New client session, resetting tunnel")
                        self.tunnel = AESTunnel(self.key)  # Reset encryption
                        await self._close_all_tcp()  # Close old connections
                        continue
                    
                    # Decrypt and handle message
                    try:
                        msg = self.tunnel.decrypt(f)
                    except Exception as e:
                        log.error("Edge decrypt failed (len=%d): %s", len(f), e)
                        continue
                    
                    if msg.startswith(b"DNS"):
                        asyncio.create_task(self._handle_dns(msg[3:5], msg[5:]))
                    elif msg.startswith(b"TCP"):
                        opcode, cid, payload = msg[3], msg[4:8], msg[8:]
                        if opcode == TCP_INIT:
                            asyncio.create_task(self._tcp_init(cid, payload))
                        elif opcode == TCP_DATA and cid in self._tcp_conns:
                            c = self._tcp_conns[cid]
                            c["w"].write(payload)
                            await c["w"].drain()
                        elif opcode in (TCP_CLOSE, TCP_ERR):
                            await self._close_tcp(cid)
        finally:
            await self._close_all_tcp()
            writer.close()
            await writer.wait_closed()

    async def _handle_dns(self, tag, q):
        try:
            resp = await self._resolve_dns(q)
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
                        async with self._writer_lock:
                            self.writer.write(encode_frame(
                                self.tunnel.encrypt(b"TCP" + bytes([TCP_DATA]) + cid + data)
                            ))
                            await self.writer.drain()
                finally:
                    async with self._writer_lock:
                        self.writer.write(encode_frame(
                            self.tunnel.encrypt(b"TCP" + bytes([TCP_CLOSE]) + cid)
                        ))
                        await self.writer.drain()
                    await self._close_tcp(cid)
            
            asyncio.create_task(pipe())
            
        except Exception as e:
            log.error("Edge TCP init failed: %s", e)
            async with self._writer_lock:
                self.writer.write(encode_frame(
                    self.tunnel.encrypt(b"TCP" + bytes([TCP_ERR]) + cid)
                ))
                await self.writer.drain()

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