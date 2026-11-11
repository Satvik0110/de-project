#!/usr/bin/env bash
# Clean slate before a demo: empties all Kafka topics, the data lake and the warehouse.
# Run with everything stopped except Kafka (scripts/stop.sh --keep-kafka).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
KT=./infra/kafka/bin/kafka-topics.sh
for t in $($KT --bootstrap-server localhost:9092 --list | grep '^security\.'); do
  $KT --bootstrap-server localhost:9092 --delete --topic "$t"
done
sleep 3
./infra/create-topics.sh >/dev/null
for g in stream-processor-v1 lake-writer-v1 warehouse-writer-v1; do
  ./infra/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --delete --group "$g" >/dev/null 2>&1 || true
done
rm -rf data_lake
PGPASSWORD=secops psql -h localhost -U secops -d secops -q -c \
  "TRUNCATE alerts, incidents, aggregates, pipeline_metrics, campaigns"
echo "reset done"
