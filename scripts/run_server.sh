#!/usr/bin/env bash
set -e
ROLE=${ROLE:-relay}
HOST=${HOST:-0.0.0.0}
PORT=${PORT:-443}
SHARED_KEY_FILE=${SHARED_KEY_FILE:-./shared.key}
python -m backend.src.server
