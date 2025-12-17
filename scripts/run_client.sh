#!/usr/bin/env bash
set -euo pipefail

# ----- EDIT THESE -----
REPO_ROOT="/path/to/vpn-simple"          # repo checkout on the client
KEY_FILE="/path/to/shared.key"           # same key as server
RELAY_HOST="<server-ip-or-dns>"          # reachable server address
RELAY_PORT=8443                          # must match server
SOCKS_HOST="127.0.0.1"
SOCKS_PORT=1080
DNS_HOST="127.0.0.1"
DNS_PORT=53530
DNS_QUERY="example.com"
API_PORT=8443                            # control API port on client
PYTHON_EXE="python"                      # or full path to python
UVICORN_EXE="uvicorn"                    # or venv path: /path/to/.venv/bin/uvicorn
# ----------------------

cd "$REPO_ROOT"

# Control API (starts DNS forwarder + SOCKS proxy)
nohup env \
  RELAY_HOST="$RELAY_HOST" \
  RELAY_PORT="$RELAY_PORT" \
  SHARED_KEY_FILE="$KEY_FILE" \
  DNS_QUERY="$DNS_QUERY" \
  DNS_LISTEN_HOST="$DNS_HOST" \
  DNS_LISTEN_PORT="$DNS_PORT" \
  SOCKS_LISTEN_HOST="$SOCKS_HOST" \
  SOCKS_LISTEN_PORT="$SOCKS_PORT" \
  LOG_LEVEL=DEBUG \
  "$UVICORN_EXE" backend.src.control_api:app --host 0.0.0.0 --port "$API_PORT" \
  > control_api.log 2>&1 &