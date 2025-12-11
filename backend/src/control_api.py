import os
import asyncio
from fastapi import FastAPI
from pydantic import BaseModel
from dnslib import DNSRecord, RCODE

from backend.src.logger import get_logger
from backend.src.server import Client
from backend.src.config import load_key
from backend.src.dns_forwarder import DNSForwarder, DNSForwarderState
from backend.src.socks5_proxy import Socks5Proxy, Socks5State  # new

log = get_logger("control_api")
app = FastAPI(title="VPN Simple Control API", version="0.1.0")

class StatusResponse(BaseModel):
    connected: bool
    relay_host: str
    relay_port: int
    dns_query: str
    error: str | None = None

_state_lock = asyncio.Lock()
_client: Client | None = None
_connected: bool = False
_last_error: str | None = None
_dns_forwarder: DNSForwarder | None = None
_socks_proxy: Socks5Proxy | None = None

def _config():
    relay_host = os.environ.get("RELAY_HOST", "127.0.0.1")
    relay_port = int(os.environ.get("RELAY_PORT", "8443"))
    key_file = os.environ.get("SHARED_KEY_FILE", "shared.key")
    dns_query = os.environ.get("DNS_QUERY", "example.com")
    dns_listen_host = os.environ.get("DNS_LISTEN_HOST", "127.0.0.1")
    dns_listen_port = int(os.environ.get("DNS_LISTEN_PORT", "5353"))
    socks_listen_host = os.environ.get("SOCKS_LISTEN_HOST", "127.0.0.1")
    socks_listen_port = int(os.environ.get("SOCKS_LISTEN_PORT", "1080"))
    return (relay_host, relay_port, key_file, dns_query,
            dns_listen_host, dns_listen_port, socks_listen_host, socks_listen_port)

async def _set_client(client: Client | None, connected: bool, err: str | None):
    global _client, _connected, _last_error
    _client = client
    _connected = connected
    _last_error = err

async def _ensure_dns_forwarder(client: Client, listen_host: str, listen_port: int):
    global _dns_forwarder
    if _dns_forwarder and _dns_forwarder.state == DNSForwarderState.RUNNING:
        return
    _dns_forwarder = DNSForwarder(client, listen_host, listen_port, log)
    await _dns_forwarder.start()

async def _stop_dns_forwarder():
    global _dns_forwarder
    if _dns_forwarder:
        await _dns_forwarder.stop()
        _dns_forwarder = None

async def _ensure_socks_proxy(client: Client, listen_host: str, listen_port: int):
    global _socks_proxy
    if _socks_proxy:
        return
    _socks_proxy = await Socks5Proxy.start(client, listen_host, listen_port, log)

async def _stop_socks_proxy():
    global _socks_proxy
    if _socks_proxy:
        await _socks_proxy.stop()
        _socks_proxy = None

@app.get("/status", response_model=StatusResponse)
async def status():
    relay_host, relay_port, _, dns_query, *_rest = _config()
    return StatusResponse(
        connected=_connected,
        relay_host=relay_host,
        relay_port=relay_port,
        dns_query=dns_query,
        error=_last_error,
    )

@app.post("/connect", response_model=StatusResponse)
async def connect():
    async with _state_lock:
        (relay_host, relay_port, key_file, dns_query,
         dns_listen_host, dns_listen_port, socks_listen_host, socks_listen_port) = _config()
        if _connected and _client:
            return StatusResponse(connected=True, relay_host=relay_host, relay_port=relay_port, dns_query=dns_query, error=None)
        try:
            key = load_key(key_file)
            client = Client(key, relay_host, relay_port)
            await _set_client(client, True, None)
            await _ensure_dns_forwarder(client, dns_listen_host, dns_listen_port)
            await _ensure_socks_proxy(client, socks_listen_host, socks_listen_port)
            return StatusResponse(connected=True, relay_host=relay_host, relay_port=relay_port, dns_query=dns_query, error=None)
        except Exception as e:  # noqa: BLE001
            log.exception("Connect failed")
            await _set_client(None, False, str(e))
            await _stop_dns_forwarder()
            await _stop_socks_proxy()
            return StatusResponse(connected=False, relay_host=relay_host, relay_port=relay_port, dns_query=dns_query, error=str(e))

@app.post("/disconnect")
async def disconnect():
    async with _state_lock:
        try:
            await _stop_dns_forwarder()
            await _stop_socks_proxy()
            if _client and hasattr(_client, "close"):
                await _client.close()
        finally:
            await _set_client(None, False, None)
    return {"disconnected": True}