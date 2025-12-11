import sys
import pathlib
import asyncio
from dnslib import DNSRecord

# Root of repo = three levels up from this file: src -> client-cli -> frontend -> vpn-simple
ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.append(str(ROOT))
sys.path.append(str(ROOT / "backend"))
sys.path.append(str(ROOT / "shared"))

from backend.src.logger import get_logger
from backend.src.server import Client
from backend.src.config import load_key
from config import RELAY_HOST, RELAY_PORT, SHARED_KEY_FILE, DNS_QUERY  # from same folder

log = get_logger("client")

async def main():
    key = load_key(SHARED_KEY_FILE)
    client = Client(key, RELAY_HOST, RELAY_PORT)
    q = DNSRecord.question(DNS_QUERY).pack()
    resp = await client.run_dns_query(q)
    if resp:
        print(DNSRecord.parse(resp))
    else:
        log.error("No response")

if __name__ == "__main__":
    asyncio.run(main())