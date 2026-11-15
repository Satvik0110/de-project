"""Pipeline health: end-to-end completeness, per-layer freshness, storage efficiency.

  completeness  events the log shippers delivered == events in Kafka == processed == in the
                lake (reconciling counts between stages is how lost data is caught)
  freshness     how far behind real time each storage layer is, and its consumer lag.
                Each layer reads Kafka in its own consumer group, so a slow writer never
                delays detection; these numbers make that visible.
  storage       Parquet vs the raw JSON it replaced, partitions written

Kafka clients are created once and used only from the single worker thread that runs
collect() (confluent_kafka clients are not thread-safe).
"""
import threading
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pyarrow.parquet as pq
from confluent_kafka import Consumer, TopicPartition

from ingest.config import KAFKA_BOOTSTRAP, TOPIC_RAW
from lake.writer import GROUP as LAKE_GROUP, LAKE_DIR
from processor.config import GROUP_ID, TOPIC_AGGREGATES, TOPIC_ALERTS, TOPIC_METRICS

SHIPPERS = ["http://127.0.10.1:8002/health", "http://127.0.0.1:8004/health"]   # target, sensor
WAREHOUSE_GROUP = "warehouse-writer-v1"
WAREHOUSE_TOPICS = [TOPIC_ALERTS, TOPIC_AGGREGATES, TOPIC_METRICS, "security.sim.campaigns"]

_lock = threading.Lock()          # Kafka clients
_files_lock = threading.Lock()    # lake footer cache
_consumers: dict[str, Consumer] = {}
_files: dict[str, dict] = {}      # parquet files are immutable: read each footer once


def _consumer(group: str) -> Consumer:
    if group not in _consumers:
        _consumers[group] = Consumer({"bootstrap.servers": KAFKA_BOOTSTRAP, "group.id": group,
                                      "enable.auto.commit": False})
    return _consumers[group]


def _partitions(c: Consumer, topic: str) -> list[TopicPartition]:
    return [TopicPartition(topic, p) for p in c.list_topics(topic, timeout=5).topics[topic].partitions]


def _end_offsets(c: Consumer, topics: list[str]) -> dict[tuple, int]:
    return {(tp.topic, tp.partition): c.get_watermark_offsets(tp, timeout=5)[1]
            for t in topics for tp in _partitions(c, t)}


def _lag(group: str, ends: dict[tuple, int]) -> int:
    """Messages not yet committed by a group, over the given partitions."""
    tps = [TopicPartition(t, p) for t, p in ends]
    committed = {(tp.topic, tp.partition): max(tp.offset, 0)
                 for tp in _consumer(group).committed(tps, timeout=5)}
    return sum(ends[k] - committed[k] for k in ends)


def lake_files() -> list[dict]:
    with _files_lock:
        return _lake_files()


def _lake_files() -> list[dict]:
    out = []
    for f in sorted(Path(LAKE_DIR).rglob("*.parquet")):
        key = str(f)
        if key not in _files:
            m = pq.read_metadata(f)
            idx = m.schema.names.index("event_time")
            newest = max((m.row_group(i).column(idx).statistics.max for i in range(m.num_row_groups)),
                         default=None)
            _files[key] = {"rows": m.num_rows, "bytes": f.stat().st_size, "partition": str(f.parent),
                           "json_bytes": int((m.metadata or {}).get(b"raw_json_bytes", 0)),
                           "newest_event": newest, "name": f.name}
        out.append(_files[key])
    return out


def collect(latest_metrics: dict | None, warehouse_write_delay_s: float | None) -> dict:
    # Shippers are read BEFORE Kafka: whatever they have counted as delivered must already
    # be in the topic, so a gap is a real loss, not two snapshots taken at different moments.
    shipped = failed = 0
    for url in SHIPPERS:
        try:
            s = httpx.get(url, timeout=2).json()["shipper"]
            shipped += s.get("sent", 0)
            failed += s.get("failed", 0) + s.get("dropped_queue_full", 0)
        except (httpx.HTTPError, KeyError, ValueError):
            pass

    with _lock:
        admin = _consumer("dashboard-admin")
        raw_ends = _end_offsets(admin, [TOPIC_RAW])
        in_kafka = sum(raw_ends.values())
        lake_lag = _lag(LAKE_GROUP, raw_ends)
        wh_lag = _lag(WAREHOUSE_GROUP, _end_offsets(admin, WAREHOUSE_TOPICS))

    files = lake_files()
    m = latest_metrics or {}
    proc_lag = m.get("consumer_lag", 0)
    stage = (m.get("stage_latency_ms") or {}).get("processing") or {}
    newest = max((f["newest_event"] for f in files if f["newest_event"]), default=None)
    with_meta = [f for f in files if f["json_bytes"]]
    parquet_b = sum(f["bytes"] for f in with_meta)
    json_b = sum(f["json_bytes"] for f in with_meta)

    return {
        "reconciliation": {
            "shipped": shipped, "shipper_failed": failed, "in_kafka": in_kafka,
            "processed": max(in_kafka - proc_lag, 0),
            "in_lake": sum(f["rows"] for f in files), "lake_pending": lake_lag,
            "lost": max(shipped - in_kafka, 0),
        },
        "tiers": [
            {"tier": "detection", "group": GROUP_ID, "lag": proc_lag,
             "freshness_s": stage["p50"] / 1000 if "p50" in stage else None},
            {"tier": "warehouse", "group": WAREHOUSE_GROUP, "lag": wh_lag,
             "freshness_s": warehouse_write_delay_s},
            {"tier": "lake", "group": LAKE_GROUP, "lag": lake_lag,
             "freshness_s": (datetime.now(timezone.utc) - newest).total_seconds() if newest else None},
        ],
        "storage": {
            "lake_files": len(files), "lake_rows": sum(f["rows"] for f in files),
            "partitions": len({f["partition"] for f in files}),
            "parquet_bytes": sum(f["bytes"] for f in files), "json_bytes": json_b,
            "compression_ratio": round(json_b / parquet_b, 1) if parquet_b else None,
        },
    }
