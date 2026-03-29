#!/usr/bin/env bash
# Run arcmint-monitor locally with automatic SSH tunneling to the production server.
# Usage: ./monitor.sh [server] [ssh-user]

set -euo pipefail

SERVER="${1:-217.216.92.184}"
SSH_USER="${2:-root}"
REMOTE_ENV="/root/arcmint/.env"
TUNNEL_PORTS=(8332 7000 7001 7002 7003)
CONTROL_SOCKET="/tmp/arcmint-monitor-ssh-tunnel.sock"

# ── Fetch .env from server if missing locally ────────────────────────────────
if [[ ! -f .env ]]; then
  echo "No local .env found — fetching from ${SSH_USER}@${SERVER}:${REMOTE_ENV} ..."
  scp "${SSH_USER}@${SERVER}:${REMOTE_ENV}" .env
fi

# ── Load .env ────────────────────────────────────────────────────────────────
set -o allexport
# shellcheck disable=SC1091
source .env
set +o allexport

# ── Kill any existing tunnel using the control socket ────────────────────────
if [[ -S "$CONTROL_SOCKET" ]]; then
  echo "Closing existing SSH tunnel ..."
  ssh -S "$CONTROL_SOCKET" -O exit "${SSH_USER}@${SERVER}" 2>/dev/null || true
  rm -f "$CONTROL_SOCKET"
fi

# ── Open SSH tunnel ───────────────────────────────────────────────────────────
tunnel_args=()
for port in "${TUNNEL_PORTS[@]}"; do
  tunnel_args+=(-L "${port}:127.0.0.1:${port}")
done

echo "Opening SSH tunnels for ports: ${TUNNEL_PORTS[*]} ..."
ssh -f -N -M -S "$CONTROL_SOCKET" \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=10 \
    "${tunnel_args[@]}" "${SSH_USER}@${SERVER}"

cleanup() {
  echo ""
  echo "Closing SSH tunnel ..."
  ssh -S "$CONTROL_SOCKET" -O exit "${SSH_USER}@${SERVER}" 2>/dev/null || true
  rm -f "$CONTROL_SOCKET"
}
trap cleanup EXIT INT TERM

# ── Run monitor ───────────────────────────────────────────────────────────────
export BITCOIN_RPC_URL="http://127.0.0.1:8332"
export COORDINATOR_URL="https://127.0.0.1:7000"
export GATEWAY_URL="https://127.0.0.1:7002"
export MERCHANT_URL="https://127.0.0.1:7003"
export SIGNER_URLS="https://127.0.0.1:7001,https://127.0.0.1:7002,https://127.0.0.1:7003"
export MONITOR_REFRESH_SECS="${MONITOR_REFRESH_SECS:-10}"

cargo run --bin arcmint-monitor
