#!/usr/bin/env bash
set -e
RELAY_HOST=${RELAY_HOST:-127.0.0.1}
RELAY_PORT=${RELAY_PORT:-443}
SHARED_KEY_FILE=${SHARED_KEY_FILE:-./shared.key}
DNS_QUERY=${DNS_QUERY:-example.com}
python -m frontend.client-cli.src.client
