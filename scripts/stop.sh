#!/usr/bin/env bash
# Stop everything started by scripts/start.sh (Kafka too, unless --keep-kafka).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
for f in logs/*.pid; do
  [ -f "$f" ] || continue
  pid=$(cat "$f"); name=$(basename "$f" .pid)
  if kill -0 "$pid" 2>/dev/null; then
    pkill -TERM -P "$pid" 2>/dev/null; kill -TERM "$pid" && echo "  stopped $name"
  fi
  rm -f "$f"
done
[ "${1:-}" = "--keep-kafka" ] || ./infra/stop-kafka.sh 2>/dev/null || true
