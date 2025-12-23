import os
import asyncio
from fastapi import FastAPI
from pydantic import BaseModel
from dnslib import DNSRecord, RCODE

from backend.src.logger import get_logger
from backend.src.server import Client, load_key
from backend.src.dns_forwarder import DNSForwarder, DNSForwarderState
from backend.src.socks5_proxy import Socks5Proxy, Socks5State
from fastapi.middleware.cors import CORSMiddleware


log = get_logger("control_api")
app = FastAPI(title="VPN Simple Control API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
_reconnect_task: asyncio.Task | None = None
_should_stay_connected: bool = False

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
        _dns_forwarder.update_client(client)
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
        _socks_proxy.update_client(client)
        return
    _socks_proxy = await Socks5Proxy.start(client, listen_host, listen_port, log)

async def _stop_socks_proxy():
    global _socks_proxy
    if _socks_proxy:
        await _socks_proxy.stop()
        _socks_proxy = None

async def _reconnect_loop():
    """Keep the client connection alive, reconnecting if needed."""
    global _client, _should_stay_connected
    
    (relay_host, relay_port, key_file, dns_query,
     dns_listen_host, dns_listen_port, socks_listen_host, socks_listen_port) = _config()
    
    # Prefer handshake-only mode when EDGE_PUBKEY_FILE is configured
    edge_pub = os.environ.get("EDGE_PUBKEY_FILE")
    if edge_pub and os.path.exists(edge_pub):
        key = None
    else:
        key = load_key(key_file)
    
    while _should_stay_connected:
        try:
            # Check if client is still connected
            if not _client or not _client.is_connected():
                log.info("Reconnecting to relay...")
                
                # Create new client
                client = Client(key, relay_host, relay_port)
                await client.connect()
                
                # Update global state
                async with _state_lock:
                    old_client = _client
                    _client = client
                    await _set_client(client, True, None)
                    
                    # Update proxy references
                    if _dns_forwarder:
                        _dns_forwarder.update_client(client)
                    if _socks_proxy:
                        _socks_proxy.update_client(client)
                    
                    # Clean up old client
                    if old_client:
                        try:
                            await old_client.close()
                        except Exception:
                            pass
                
                log.info("Reconnected successfully")
            
            # Wait before checking again
            await asyncio.sleep(5)
            
        except Exception as e:
            log.error("Reconnect loop error: %s", e)
            await asyncio.sleep(2)

@app.get("/status", response_model=StatusResponse)
async def status():
    relay_host, relay_port, _, dns_query, *_rest = _config()
    return StatusResponse(
        connected=_client.is_connected() if _client else False,
        relay_host=relay_host,
        relay_port=relay_port,
        dns_query=dns_query,
        error=_last_error,
    )

@app.post("/connect", response_model=StatusResponse)
async def connect():
    global _reconnect_task, _should_stay_connected
    
    async with _state_lock:
        (relay_host, relay_port, key_file, dns_query,
         dns_listen_host, dns_listen_port, socks_listen_host, socks_listen_port) = _config()
        
        # If already connected and reconnect loop is running, just return status
        if _client and _client.is_connected() and _reconnect_task and not _reconnect_task.done():
            log.info("Already connected to relay")
            return StatusResponse(
                connected=True, 
                relay_host=relay_host, 
                relay_port=relay_port, 
                dns_query=dns_query, 
                error=None
            )
        
        try:
            # Stop old reconnect task if exists
            if _reconnect_task and not _reconnect_task.done():
                _should_stay_connected = False
                _reconnect_task.cancel()
                try:
                    await _reconnect_task
                except asyncio.CancelledError:
                    pass
            
            # Create initial connection
            edge_pub = os.environ.get("EDGE_PUBKEY_FILE")
            if edge_pub and os.path.exists(edge_pub):
                client = Client(None, relay_host, relay_port)
            else:
                key = load_key(key_file)
                client = Client(key, relay_host, relay_port)
            
            await client.connect()
            await _set_client(client, True, None)
            
            # Start DNS forwarder and SOCKS proxy
            await _ensure_dns_forwarder(client, dns_listen_host, dns_listen_port)
            await _ensure_socks_proxy(client, socks_listen_host, socks_listen_port)
            
            # Start reconnect loop to maintain connection
            _should_stay_connected = True
            _reconnect_task = asyncio.create_task(_reconnect_loop())
            
            log.info("Connected to relay and started reconnect loop")
            return StatusResponse(
                connected=True, 
                relay_host=relay_host, 
                relay_port=relay_port, 
                dns_query=dns_query, 
                error=None
            )
            
        except Exception as e:
            log.exception("Connect failed")
            await _set_client(None, False, str(e))
            await _stop_dns_forwarder()
            await _stop_socks_proxy()
            _should_stay_connected = False
            return StatusResponse(
                connected=False, 
                relay_host=relay_host, 
                relay_port=relay_port, 
                dns_query=dns_query, 
                error=str(e)
            )

@app.post("/disconnect")
async def disconnect():
    global _reconnect_task, _should_stay_connected
    
    async with _state_lock:
        try:
            # Stop reconnect loop
            _should_stay_connected = False
            if _reconnect_task and not _reconnect_task.done():
                _reconnect_task.cancel()
                try:
                    await _reconnect_task
                except asyncio.CancelledError:
                    pass
            _reconnect_task = None
            
            # Stop services
            await _stop_dns_forwarder()
            await _stop_socks_proxy()
            
            # Close client
            if _client and hasattr(_client, "close"):
                await _client.close()
        finally:
            await _set_client(None, False, None)
    
    log.info("Disconnected from relay")
    return {"disconnected": True}

@app.on_event("shutdown")
async def shutdown():
    """Clean up on application shutdown."""
    global _should_stay_connected
    _should_stay_connected = False
    if _reconnect_task:
        _reconnect_task.cancel()
    await _stop_dns_forwarder()
    await _stop_socks_proxy()
    if _client:
        await _client.close()