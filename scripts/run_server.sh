#!/usr/bin/env bash
set -euo pipefail

# ----- EDIT THESE -----
REPO_ROOT="/path/to/vpn-simple"      # repo checkout on the server
KEY_FILE="/path/to/shared.key"       # shared key on the server
RELAY_HOST="0.0.0.0"                 # listen on all interfaces
RELAY_PORT=8443                      # open this TCP port in firewall
UPSTREAM_DNS="1.1.1.1"               # upstream DNS for edge
PYTHON_EXE="python"                  # or full path to python
# ----------------------

cd "$REPO_ROOT"

# Relay
nohup env \
  ROLE=relay \
  RELAY_HOST="$RELAY_HOST" \
  RELAY_PORT="$RELAY_PORT" \
  SHARED_KEY_FILE="$KEY_FILE" \
  LOG_LEVEL=DEBUG \
  "$PYTHON_EXE" -m backend.src.server \
  > relay.log 2>&1 &

# Edge (talks to relay on same box; if separate, set RELAY_HOST to server IP)
nohup env \
  ROLE=edge \
  RELAY_HOST="127.0.0.1" \
  RELAY_PORT="$RELAY_PORT" \
  UPSTREAM_DNS="$UPSTREAM_DNS" \
  SHARED_KEY_FILE="$KEY_FILE" \
  LOG_LEVEL=DEBUG \
  "$PYTHON_EXE" -m backend.src.server \
  > edge.log 2>&1 &