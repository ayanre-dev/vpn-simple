#!/usr/bin/env bash
set -e
cd frontend/web-ui
npm install
npm run dev -- --host 0.0.0.0 --port 4173
