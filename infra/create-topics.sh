#!/usr/bin/env bash
# Create the two project topics. Idempotent: skips topics that already exist.
set -euo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KT="$INFRA_DIR/kafka/bin/kafka-topics.sh"
BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"
RETENTION_MS=259200000   # 72h, matches log.retention.hours

if ! "$KT" --bootstrap-server "$BOOTSTRAP" --list > /dev/null 2>&1; then
  echo "Cannot reach a broker at $BOOTSTRAP. Is it running? (./infra/start-kafka.sh)"
  exit 1
fi

existing="$("$KT" --bootstrap-server "$BOOTSTRAP" --list)"

create() {  # name partitions
  if grep -qx "$1" <<< "$existing"; then
    echo "   $1 already exists, skipping"
  else
    "$KT" --bootstrap-server "$BOOTSTRAP" --create --topic "$1" \
      --partitions "$2" --replication-factor 1 \
      --config retention.ms=$RETENTION_MS 2>/dev/null
    echo "   created $1 ($2 partition/s)"
  fi
}

# raw: 3 partitions so events can be spread by src_ip key and consumed in parallel
create security.events.raw 3
# dlq: low volume, ordering across it does not matter
create security.events.dlq 1

echo
"$KT" --bootstrap-server "$BOOTSTRAP" --list
