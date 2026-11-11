#!/usr/bin/env bash
# Start the whole platform in the background. Logs: logs/<service>.log. Stop: scripts/stop.sh
# Prerequisites (one time): infra/setup-kafka.sh, infra/setup-postgres.sh, npm install in both UIs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p logs
[ -f .env ] && { set -a; . ./.env; set +a; }
PY="$ROOT/venv/bin/python"

if ! ./infra/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; then
  ./infra/start-kafka.sh -d
  until ./infra/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; do sleep 1; done
fi
./infra/create-topics.sh >/dev/null

start() {  # name, command...
  local name=$1; shift
  if [ -f "logs/$name.pid" ] && kill -0 "$(cat "logs/$name.pid")" 2>/dev/null; then
    echo "  $name already running"; return
  fi
  nohup "$@" > "logs/$name.log" 2>&1 &
  echo $! > "logs/$name.pid"
  echo "  started $name"
}

# blue side: ingest, detection, storage, dashboard
start ingest     "$PY" -m uvicorn ingest.main:app --port 8000
start processor  "$PY" -m processor.main
start lake       "$PY" -m lake.writer
start warehouse  "$PY" -m warehouse.writer
start dashboard  "$PY" -m uvicorn dashboard.api:app --port 8003
# defended systems: they write the security log
start target     "$PY" -m uvicorn target.main:app --host 127.0.10.1 --port 8002
start sensor     "$PY" -m uvicorn sensor.main:app --port 8004
# red side
start simulator  "$PY" -m uvicorn simulator.main:app --port 8001
start red-ui     npm --prefix frontend run dev -- --port 5173 --strictPort
start blue-ui    npm --prefix dashboard/ui run dev

echo
echo "Red team console : http://localhost:5173"
echo "SOC dashboard    : http://localhost:5174"
