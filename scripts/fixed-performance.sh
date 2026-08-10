#!/usr/bin/env bash
set -euo pipefail

workspace_root="${GITHUB_WORKSPACE:-$(pwd)}"
workspace_root="$(cd "$workspace_root" && pwd)"
log_path="${FRP_FIXED_PERF_LOG_PATH:-$workspace_root/performance-fixed-2vcpu-2g.log}"
case "$log_path" in
  "$workspace_root"/*) ;;
  *)
    echo "FRP_FIXED_PERF_LOG_PATH must be inside the checked-out workspace: $workspace_root" >&2
    exit 2
    ;;
esac

log_name="${log_path#"$workspace_root/"}"
if [[ -z "$log_name" || "$log_name" == */* ]]; then
  echo "FRP_FIXED_PERF_LOG_PATH must name a file directly under the workspace" >&2
  exit 2
fi

image="${FRP_FIXED_PERF_IMAGE:-golang:1.25-bookworm@sha256:908f8ff2ec296df2f349563072c7925775cd28b50361a52ed834a8a37399b9bf}"
container_log_path="/workspace/$log_name"

docker run --rm \
  --cpus=2 \
  --memory=2g \
  --memory-swap=2g \
  --mount "type=bind,src=$workspace_root,dst=/workspace" \
  --workdir /workspace \
  --env "FRP_FIXED_PERF_LOG=$container_log_path" \
  "$image" \
  bash -c '
    set -euo pipefail
    export FRP_PERF=1 FRP_PERF_SCALE=1
    export GOCACHE=/tmp/frp-go-build GOMODCACHE=/tmp/frp-go-mod
    {
      printf "%s\n" "environment: Ubuntu 24.04 Docker; cpus=2; memory=2GiB; memory_swap=2GiB; sqlite=WAL; image=$HOSTNAME"
      cd /workspace/server
      go test -v -run "^TestPerformance(Baseline|Scale|SessionReplacement)$" -count=1 ./internal/httpapi
      cd /workspace/client
      go test -v -run "^TestPerformanceConfigSubmitToClientApply$" -count=1 ./internal/app
    } 2>&1 | tee "$FRP_FIXED_PERF_LOG"
  '
