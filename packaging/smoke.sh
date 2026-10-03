#!/usr/bin/env bash
# Launches an AppImage with --no-browser and waits for /api/health.
# Uses only bash (no curl), so it runs in bare distro containers.
# Usage: packaging/smoke.sh Stackwell-x.y.z-x86_64.AppImage [extra AppImage args]
set -euo pipefail
APPIMAGE="$1"; shift
PORT=47800
export XDG_DATA_HOME="$(mktemp -d)"

"$APPIMAGE" "$@" --no-browser -port "$PORT" &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

for _ in $(seq 1 60); do
  if exec 3<>"/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
    printf 'GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3
    RESP="$(cat <&3)"
    exec 3>&-
    if grep -q '"status":"ok"' <<<"$RESP"; then
      echo "healthy: $(tail -n1 <<<"$RESP")"
      exit 0
    fi
  fi
  sleep 0.5
done
echo "Stackwell did not become healthy within 30s" >&2
exit 1
