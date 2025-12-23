import struct
import socket
import ssl
import os

def encode_frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload

def decode_frames(buf: bytearray):
    frames = []
    offset = 0
    while len(buf) - offset >= 4:
        (length,) = struct.unpack_from("!I", buf, offset)
        if len(buf) - offset - 4 < length:
            break
        start = offset + 4
        end = start + length
        frames.append(bytes(buf[start:end]))
        offset = end
    if offset:
        del buf[:offset]
    return frames

def enable_keepalive(sock: socket.socket):
    """Enable TCP keepalive on a socket to prevent connection drops."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass

def maybe_tls():
    return ssl.create_default_context() if os.environ.get("USE_TLS") == "1" else None

async def writer_task(writer, queue, name, log):
    """Generic writer task to pump data from a queue to a stream writer."""
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
