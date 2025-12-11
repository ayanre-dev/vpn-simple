import asyncio
import socket
from shared.utils import encode_frame, decode_frames

class DNSRouter:
    def __init__(self, upstream: str = "1.1.1.1", port: int = 53):
        self.upstream = upstream
        self.port = port

    async def resolve(self, query: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._udp_query, query)

    def _udp_query(self, query: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(query, (self.upstream, self.port))
            data, _ = s.recvfrom(2048)
            return data
