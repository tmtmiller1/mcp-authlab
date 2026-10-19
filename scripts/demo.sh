#!/usr/bin/env bash
# Start a fixture profile, scan it with a valid token and a foreign-audience token, stop it.
# Usage: scripts/demo.sh [profile] [extra scan args...]
set -euo pipefail
profile="${1:-reference}"; shift || true
port="${PORT:-8765}"
python3 -m mcp_authlab fixture --profile "$profile" --port "$port" --print-token >"/tmp/mcp-authlab-$profile.token" 2>/dev/null &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do [ -s "/tmp/mcp-authlab-$profile.token" ] && break; sleep 0.1; done
token="$(head -1 "/tmp/mcp-authlab-$profile.token")"
foreign="$(curl -s "http://127.0.0.1:$port/dev/token?aud=https://other.example/mcp")"
python3 -m mcp_authlab scan "http://127.0.0.1:$port/mcp" --token "$token" --foreign-token "$foreign" "$@"
