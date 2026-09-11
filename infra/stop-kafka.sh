#!/usr/bin/env bash
set -euo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$INFRA_DIR/kafka/bin/kafka-server-stop.sh"
