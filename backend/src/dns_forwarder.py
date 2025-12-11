import asyncio
from enum import Enum, auto
from typing import Optional
from dnslib import DNSRecord, DNSHeader, RCODE

class DNSForwarderState(Enum):
    STOPPED = auto()
    RUNNING = auto()

class DNSForwarder(asyncio.DatagramProtocol):
    """
    UDP DNS forwarder: listens locally and forwards queries via the tunnel client.
    """
    def __init__(self, client, listen_host: str, listen_port: int, log):
        self.client = client
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.log = log
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.state = DNSForwarderState.STOPPED

    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=(self.listen_host, self.listen_port),
        )
        self.state = DNSForwarderState.RUNNING
        self.log.info("DNS forwarder listening on %s:%s", self.listen_host, self.listen_port)

    async def stop(self):
        if self.transport:
            self.transport.close()
        self.state = DNSForwarderState.STOPPED
        self.log.info("DNS forwarder stopped")

    def datagram_received(self, data: bytes, addr):
        asyncio.create_task(self.handle_query(data, addr))

    async def handle_query(self, data: bytes, addr):
        try:
            # Forward over tunnel
            resp = await self.client.run_dns_query(data)
            if resp is None:
                # Send SERVFAIL
                q = DNSRecord.parse(data)
                r = DNSRecord(
                    DNSHeader(
                        id=q.header.id,
                        qr=1,
                        aa=0,
                        ra=1,
                        rd=q.header.rd,
                        rcode=RCODE.SERVFAIL,
                    ),
                    q.questions,
                )
                resp = r.pack()
            self.transport.sendto(resp, addr)
        except Exception as e:  # noqa: BLE001
            try:
                q = DNSRecord.parse(data)
                r = DNSRecord(
                    DNSHeader(
                        id=q.header.id,
                        qr=1,
                        aa=0,
                        ra=1,
                        rd=q.header.rd,
                        rcode=RCODE.SERVFAIL,
                    ),
                    q.questions,
                )
                self.transport.sendto(r.pack(), addr)
            except Exception:
                pass
            self.log.exception("DNS forwarder error: %s", e)