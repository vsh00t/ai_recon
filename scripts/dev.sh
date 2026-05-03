#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

(cd apps/api && uvicorn ai_recon_api.main:app --reload --port 8000) &
API_PID=$!
trap "kill $API_PID 2>/dev/null || true" EXIT

(cd apps/web && npm run dev)
