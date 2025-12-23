import asyncio
from enum import Enum, auto
from typing import Optional


class Socks5State(Enum):
    STOPPED = auto()
    RUNNING = auto()


class Socks5Proxy:
    """
    Minimal SOCKS5 proxy (no-auth, CONNECT only).
    Uses client.open_tcp(host, port) returning an object with send/recv/close.
    """

    def __init__(self, client, log):
        self.client = client
        self.log = log
        self.state = Socks5State.STOPPED
        self._server: Optional[asyncio.base_events.Server] = None
        self._tasks: set[asyncio.Task] = set()

    @classmethod
    async def start(cls, client, listen_host: str, listen_port: int, log):
        instance = cls(client, log)
        instance._server = await asyncio.start_server(
            instance._handle_client, host=listen_host, port=listen_port
        )
        instance.state = Socks5State.RUNNING
        log.info("SOCKS5 proxy listening on %s:%s", listen_host, listen_port)
        return instance

    async def stop(self):
        self.state = Socks5State.STOPPED
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for t in list(self._tasks):
            t.cancel()
        self._tasks.clear()

    def update_client(self, client):
        """Update the client reference for new sessions."""
        self.client = client
        self.log.info("SOCKS5: client reference updated")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        self.log.info("SOCKS: new client %s", addr)
        try:
            # Greeting
            data = await reader.readexactly(2)
            ver = data[0]
            if ver != 5:
                self.log.warning("SOCKS: bad version %s from %s", ver, addr)
                writer.close()
                await writer.wait_closed()
                return
            nmethods = data[1]
            methods = await reader.readexactly(nmethods)
            self.log.debug("SOCKS: methods %s from %s", methods, addr)
            # no-auth
            writer.write(b"\x05\x00")
            await writer.drain()

            # Request
            hdr = await reader.readexactly(4)
            ver, cmd, _rsv, atyp = hdr
            if ver != 5 or cmd != 1:  # CONNECT only
                self.log.warning("SOCKS: unsupported cmd %s from %s", cmd, addr)
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if atyp == 1:
                addr_bytes = await reader.readexactly(4)
                host = ".".join(str(b) for b in addr_bytes)
            elif atyp == 3:
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            elif atyp == 4:
                addr_bytes = await reader.readexactly(16)
                host = ":".join(f"{addr_bytes[i]<<8 | addr_bytes[i+1]:x}" for i in range(0, 16, 2))
            else:
                self.log.warning("SOCKS: bad atyp %s from %s", atyp, addr)
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            port = int.from_bytes(await reader.readexactly(2), "big")
            self.log.info("SOCKS: connect %s:%s from %s", host, port, addr)

            try:
                conn = await self.client.open_tcp(host, port)
                self.log.info("SOCKS: open_tcp ok %s:%s", host, port)
            except Exception as e:
                err_msg = str(e) or e.__class__.__name__
                self.log.error("SOCKS: open_tcp failed %s:%s (%s)", host, port, err_msg)
                writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Success reply (bound addr/port zeros)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            async def pipe_in():
                try:
                    while True:
                        chunk = await reader.read(4096)
                        if not chunk:
                            break
                        await conn.send(chunk)
                except asyncio.CancelledError:
                    pass
                finally:
                    await conn.close()

            async def pipe_out():
                try:
                    while True:
                        chunk = await conn.recv()
                        if not chunk:
                            break
                        writer.write(chunk)
                        await writer.drain()
                except asyncio.CancelledError:
                    pass
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            t1 = asyncio.create_task(pipe_in())
            t2 = asyncio.create_task(pipe_out())
            self._tasks.update({t1, t2})
            done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            self._tasks.difference_update({t1, t2})
            self.log.info("SOCKS: closing %s:%s from %s", host, port, addr)
        except Exception as e:
            self.log.exception("SOCKS: error with %s (%s)", addr, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass