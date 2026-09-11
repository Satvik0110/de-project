"""Central config for the ingest service. Override via environment variables."""
import os

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")

TOPIC_RAW = os.getenv("TOPIC_RAW", "security.events.raw")
TOPIC_DLQ = os.getenv("TOPIC_DLQ", "security.events.dlq")

SCHEMA_VERSION = 1
