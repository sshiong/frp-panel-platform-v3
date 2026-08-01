#!/usr/bin/env bash
set -euo pipefail

required=(FRP_E2E_FRPS_BINARY FRP_E2E_FRPS_CONFIG FRP_E2E_FRPC_BINARY FRP_E2E_FRPC_CONFIG FRP_E2E_URL)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "$name is required; see docs/frp-plugin-e2e.md" >&2
    exit 2
  fi
done

for binary in "$FRP_E2E_FRPS_BINARY" "$FRP_E2E_FRPC_BINARY"; do
  if [[ ! -x "$binary" ]]; then
    echo "fixed FRP binary is not executable: $binary" >&2
    exit 2
  fi
done
for config in "$FRP_E2E_FRPS_CONFIG" "$FRP_E2E_FRPC_CONFIG"; do
  if [[ ! -f "$config" ]]; then
    echo "FRP E2E config is missing: $config" >&2
    exit 2
  fi
done

verify_hash() {
  local binary="$1"
  local expected="$2"
  if [[ -z "$expected" ]]; then
    return 0
  fi
  local actual
  actual="$(shasum -a 256 "$binary" | awk '{print $1}')"
  if [[ "$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')" ]]; then
    echo "SHA-256 mismatch for $binary: got $actual" >&2
    exit 1
  fi
}

verify_hash "$FRP_E2E_FRPS_BINARY" "${FRP_E2E_FRPS_SHA256:-}"
verify_hash "$FRP_E2E_FRPC_BINARY" "${FRP_E2E_FRPC_SHA256:-}"
"$FRP_E2E_FRPS_BINARY" verify -c "$FRP_E2E_FRPS_CONFIG"
"$FRP_E2E_FRPC_BINARY" verify -c "$FRP_E2E_FRPC_CONFIG"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/frp-panel-e2e.XXXXXX")"
frps_log="$workdir/frps.log"
frpc_log="$workdir/frpc.log"
frps_pid=""
frpc_pid=""
cleanup() {
  set +e
  [[ -n "$frpc_pid" ]] && kill -TERM "$frpc_pid" 2>/dev/null
  [[ -n "$frps_pid" ]] && kill -TERM "$frps_pid" 2>/dev/null
  [[ -n "$frpc_pid" ]] && wait "$frpc_pid" 2>/dev/null
  [[ -n "$frps_pid" ]] && wait "$frps_pid" 2>/dev/null
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

"$FRP_E2E_FRPS_BINARY" -c "$FRP_E2E_FRPS_CONFIG" >"$frps_log" 2>&1 &
frps_pid=$!

if [[ -n "${FRP_E2E_FRPS_READY_PORT:-}" ]]; then
  ready_deadline=$((SECONDS + ${FRP_E2E_READY_WAIT_SECONDS:-15}))
  while (( SECONDS < ready_deadline )); do
    if (exec 3<>"/dev/tcp/${FRP_E2E_FRPS_READY_HOST:-127.0.0.1}/${FRP_E2E_FRPS_READY_PORT}") 2>/dev/null; then
      exec 3>&-
      break
    fi
    if ! kill -0 "$frps_pid" 2>/dev/null; then
      echo "FRPS exited before its control port became ready" >&2
      sed -n '1,160p' "$frps_log" >&2 || true
      exit 1
    fi
    sleep 1
  done
  if ! (exec 3<>"/dev/tcp/${FRP_E2E_FRPS_READY_HOST:-127.0.0.1}/${FRP_E2E_FRPS_READY_PORT}") 2>/dev/null; then
    echo "FRPS control port did not become ready" >&2
    sed -n '1,160p' "$frps_log" >&2 || true
    exit 1
  fi
  exec 3>&-
fi

"$FRP_E2E_FRPC_BINARY" -c "$FRP_E2E_FRPC_CONFIG" >"$frpc_log" 2>&1 &
frpc_pid=$!

deadline=$((SECONDS + ${FRP_E2E_WAIT_SECONDS:-30}))
while (( SECONDS < deadline )); do
  if curl --fail --silent --show-error --max-time 2 "$FRP_E2E_URL" >/dev/null; then
    echo "FRPS/FRPC network E2E passed: $FRP_E2E_URL"
    exit 0
  fi
  if ! kill -0 "$frps_pid" 2>/dev/null || ! kill -0 "$frpc_pid" 2>/dev/null; then
    echo "FRPS or FRPC exited before the proxy became reachable" >&2
    sed -n '1,160p' "$frps_log" >&2 || true
    sed -n '1,160p' "$frpc_log" >&2 || true
    exit 1
  fi
  sleep 1
done

echo "FRPS/FRPC network E2E timed out after ${FRP_E2E_WAIT_SECONDS:-30}s" >&2
sed -n '1,160p' "$frps_log" >&2 || true
sed -n '1,160p' "$frpc_log" >&2 || true
exit 1
