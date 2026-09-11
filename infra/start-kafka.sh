#!/usr/bin/env bash
# Start the Kafka broker in the foreground (Ctrl-C to stop).
# Pass -d to run it as a background daemon instead.
set -euo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KAFKA_HOME="$INFRA_DIR/kafka"

if [ ! -f "$KAFKA_HOME/config/server.properties" ]; then
  echo "Kafka not set up yet. Run ./infra/setup-kafka.sh first."
  exit 1
fi

if [ "${1:-}" = "-d" ]; then
  "$KAFKA_HOME/bin/kafka-server-start.sh" -daemon "$KAFKA_HOME/config/server.properties"
  echo "broker starting in background; stop it with ./infra/stop-kafka.sh"
else
  exec "$KAFKA_HOME/bin/kafka-server-start.sh" "$KAFKA_HOME/config/server.properties"
fi
