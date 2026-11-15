#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$ROOT/.tools/bin:$PATH"
export KUBECONFIG="$ROOT/.runtime/kubeconfig"
export AWS_EC2_METADATA_DISABLED=true
mkdir -p "$ROOT/.runtime"
cd "$ROOT"
k() { kubectl --context kind-p001 "$@"; }
owned() {
  [[ -f .runtime/owner ]] && [[ "$(cat .runtime/owner)" == "p001-owned-v1" ]] || {
    echo 'BLOCKED: ownership marker absent; refusing to adopt/delete an existing cluster' >&2; return 1;
  }
}
forward() {
  local ns="$1" svc="$2" port="$3" remote="$4"
  if [[ -f ".runtime/forward-$port.pid" ]] && kill -0 "$(cat ".runtime/forward-$port.pid")" 2>/dev/null; then return; fi
  python3 - "$port" <<'CHECK'
import socket,sys
s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));s.close()
CHECK
  k -n "$ns" port-forward --address 127.0.0.1 "svc/$svc" "$port:$remote" >".runtime/forward-$port.log" 2>&1 &
  echo "$!" >".runtime/forward-$port.pid"
  for i in {1..30}; do
    if curl -fsS --max-time 1 "http://127.0.0.1:$port/${5:-healthz}" >/dev/null 2>&1; then return; fi
    if ! kill -0 "$(cat ".runtime/forward-$port.pid")" 2>/dev/null; then cat ".runtime/forward-$port.log"; return 1; fi
    sleep 1
  done
  echo "BLOCKED: $svc readiness on $port" >&2;return 1
}
