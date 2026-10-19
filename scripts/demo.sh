#!/usr/bin/env bash
# Start a fixture profile, log in to it without a browser, scan it with the stored tokens, stop it.
# Profiles whose authorization server is unreachable (mismatch) fall back to tokens minted by /dev/token.
# Usage: scripts/demo.sh [profile] [extra scan args...]
set -euo pipefail
profile="${1:-reference}"; shift || true
port="${PORT:-8765}"
work="$(mktemp -d)"
trap 'kill "${pid:-}" 2>/dev/null; wait "${pid:-}" 2>/dev/null; rm -rf "$work"' EXIT
export MCP_AUTHLAB_TOKENS="$work/tokens.json"
python3 -m mcp_authlab fixture --profile "$profile" --port "$port" --auto-consent --print-token >"$work/token" 2>/dev/null &
pid=$!
for _ in $(seq 1 50); do [ -s "$work/token" ] && break; sleep 0.1; done
url="http://127.0.0.1:$port/mcp"
# Profiles that skip dynamic registration accept any client_id, which is what --client-id is for.
login() { python3 -m mcp_authlab login "$url" --no-browser --no-color --timeout 10 "$@" >"$work/login.txt" 2>&1; }
if login || { grep -q "offer dynamic registration" "$work/login.txt" && login --client-id demo-client; }; then
  python3 -m mcp_authlab scan "$url" "$@"
else
  echo "login unavailable for profile $profile ($(tail -1 "$work/login.txt")); scanning with minted tokens" >&2
  token="$(head -1 "$work/token")"
  foreign="$(curl -s "http://127.0.0.1:$port/dev/token?aud=https://other.example/mcp")"
  python3 -m mcp_authlab scan "$url" --token "$token" --foreign-token "$foreign" "$@"
fi
