#!/usr/bin/env bash
# One-time Kafka setup. Downloads Kafka, applies our config, formats KRaft storage.
# Safe to re-run: it refuses to reformat an existing cluster.
set -euo pipefail

KAFKA_VERSION="4.3.1"
SCALA_VERSION="2.13"
TARBALL="kafka_${SCALA_VERSION}-${KAFKA_VERSION}.tgz"

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KAFKA_HOME="$INFRA_DIR/kafka"
DATA_DIR="$INFRA_DIR/kafka-data"

if [ -d "$DATA_DIR" ] && [ -f "$DATA_DIR/meta.properties" ]; then
  echo "Cluster already formatted at $DATA_DIR"
  echo "Delete that directory first if you really want to start over (this wipes all events)."
  exit 0
fi

if [ ! -d "$KAFKA_HOME" ]; then
  echo ">> downloading Kafka $KAFKA_VERSION (~130MB)"
  cd "$INFRA_DIR"
  curl -sSL -O "https://dlcdn.apache.org/kafka/${KAFKA_VERSION}/${TARBALL}"
  curl -sSL -O "https://downloads.apache.org/kafka/${KAFKA_VERSION}/${TARBALL}.sha512"

  echo ">> verifying checksum"
  expected=$(tr -d ' \n' < "${TARBALL}.sha512" | sed 's/.*://' | tr 'A-Z' 'a-z')
  actual=$(sha512sum "$TARBALL" | cut -d' ' -f1)
  if [ "$expected" != "$actual" ]; then
    echo "CHECKSUM MISMATCH -- refusing to continue"
    exit 1
  fi
  echo "   checksum ok"

  tar -xzf "$TARBALL"
  mv "kafka_${SCALA_VERSION}-${KAFKA_VERSION}" kafka
  rm -f "${TARBALL}" "${TARBALL}.sha512"
fi

echo ">> applying project config"
# log.dirs must be an absolute path, and it differs per machine, so it is a
# placeholder in the tracked template and filled in here.
sed "s#__KAFKA_DATA_DIR__#${DATA_DIR}#" \
  "$INFRA_DIR/server.properties.template" > "$KAFKA_HOME/config/server.properties"

echo ">> formatting KRaft storage (one time only)"
CLUSTER_ID="$("$KAFKA_HOME/bin/kafka-storage.sh" random-uuid)"
"$KAFKA_HOME/bin/kafka-storage.sh" format --standalone \
  -t "$CLUSTER_ID" -c "$KAFKA_HOME/config/server.properties" > /dev/null
echo "   cluster id: $CLUSTER_ID"

echo
echo "Done. Next:"
echo "  ./infra/start-kafka.sh      # start the broker"
echo "  ./infra/create-topics.sh    # create the two topics (broker must be up)"
