#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "linux fault injection requires a Linux runner" >&2
  exit 2
fi

mount_root="$(mktemp -d "${TMPDIR:-/tmp}/frp-panel-fault.XXXXXX")"
mount_point="${mount_root}/volume"
mkdir -p "${mount_point}"

cleanup() {
  sudo umount "${mount_point}" 2>/dev/null || true
  rmdir "${mount_point}" 2>/dev/null || true
  rmdir "${mount_root}" 2>/dev/null || true
}
trap cleanup EXIT

sudo mount -t tmpfs -o size=32m,mode=0777 tmpfs "${mount_point}"

echo "== disk-full: atomic last-good protection =="
(cd server && FRP_DISK_FULL_DIR="${mount_point}" go test ./internal/router -run '^TestAtomicWriteDiskFull$' -count=1 -v)

echo "== clock-skew: provider/ACME fail-safe checks =="
(cd server && go test ./internal/clock ./internal/acme ./internal/providers/cloudflare -count=1)
