"""Data lake writer (FR3): every raw event, unmodified, as Parquet.

An independent consumer group on security.events.raw, so lake I/O never sits on the
detection path (Kafka gives each group its own copy of the stream).

  - micro-batches: flush at FLUSH_ROWS events or FLUSH_S seconds, whichever comes first
  - Hive-style partitions from each event's event_time: year=/month=/day=/hour=
    (a late event still lands in its true hour; queries prune whole folders)
  - Snappy-compressed Parquet; per-column min/max statistics let DuckDB/pandas skip row groups
  - offsets committed only after the files are on disk: at-least-once. A crash between
    write and commit can store an event twice, so readers dedup on event_id
    (lake.reader does it for you, lake.compact removes them for good).
  - a record that cannot be parsed is not dropped: it goes, byte for byte, to
    data_lake/_quarantine/ as JSON lines with its Kafka coordinates and the error.
    The leading underscore keeps it out of Parquet readers (pyarrow skips _ and . paths).

Run:  python -m lake.writer
"""
import json
import logging
import os
import signal
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from confluent_kafka import Consumer, KafkaException

from ingest.config import KAFKA_BOOTSTRAP, TOPIC_RAW

LAKE_DIR = Path(os.getenv("LAKE_DIR", Path(__file__).resolve().parent.parent / "data_lake"))
FLUSH_ROWS = int(os.getenv("LAKE_FLUSH_ROWS", "5000"))
FLUSH_S = float(os.getenv("LAKE_FLUSH_S", "30"))
GROUP = os.getenv("LAKE_GROUP", "lake-writer-v1")

# The raw contract, column for column. raw_payload is free-form, so it is kept as JSON text.
SCHEMA = pa.schema([
    ("event_id", pa.string()), ("schema_version", pa.int32()),
    ("event_time", pa.timestamp("us", tz="UTC")), ("ingest_time", pa.timestamp("us", tz="UTC")),
    ("source_type", pa.string()), ("src_ip", pa.string()), ("dest_ip_port", pa.string()),
    ("user", pa.string()), ("status", pa.string()), ("raw_payload", pa.string()),
    ("kafka_partition", pa.int32()), ("kafka_offset", pa.int64()),   # provenance
])

log = logging.getLogger("lake")
running = True


def to_row(value: bytes, partition: int, offset: int) -> dict:
    ev = json.loads(value)
    return {
        "event_id": ev["event_id"], "schema_version": ev.get("schema_version", 1),
        "event_time": datetime.fromisoformat(ev["event_time"]),
        "ingest_time": datetime.fromisoformat(ev["ingest_time"]) if ev.get("ingest_time") else None,
        "source_type": ev["source_type"], "src_ip": ev["src_ip"], "dest_ip_port": ev.get("dest_ip_port"),
        "user": ev.get("user"), "status": ev["status"],
        "raw_payload": json.dumps(ev["raw_payload"]) if ev.get("raw_payload") is not None else None,
        "kafka_partition": partition, "kafka_offset": offset,
    }


def flush(rows: list[dict], lake_dir: Path = LAKE_DIR) -> list[Path]:
    """Write one file per hour partition touched by this batch. Returns the paths written."""
    by_hour = defaultdict(list)
    for r in rows:
        t = r["event_time"].astimezone(timezone.utc)
        by_hour[(t.year, t.month, t.day, t.hour)].append(r)
    written = []
    for (y, m, d, h), part in by_hour.items():
        folder = lake_dir / f"year={y}" / f"month={m:02d}" / f"day={d:02d}" / f"hour={h:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"part-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}.parquet"
        tmp = path.with_suffix(".tmp")
        pq.write_table(pa.Table.from_pylist(part, schema=SCHEMA), tmp, compression="snappy")
        tmp.rename(path)        # readers never see a half-written file
        written.append(path)
    return written


def quarantine(records: list[dict], lake_dir: Path = LAKE_DIR) -> Path:
    """Append unparseable records to today's quarantine file. Returns its path."""
    folder = lake_dir / "_quarantine"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{datetime.now(timezone.utc):%Y-%m-%d}.jsonl"
    with path.open("a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return path


def bad_record(value: bytes, partition: int, offset: int, exc: Exception) -> dict:
    return {"kafka_partition": partition, "kafka_offset": offset,
            "error": f"{type(exc).__name__}: {exc}", "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "value": value.decode("utf-8", errors="replace") if value is not None else None}


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    signal.signal(signal.SIGINT, lambda *_: globals().update(running=False))
    signal.signal(signal.SIGTERM, lambda *_: globals().update(running=False))

    consumer = Consumer({"bootstrap.servers": KAFKA_BOOTSTRAP, "group.id": GROUP,
                         "auto.offset.reset": "earliest", "enable.auto.commit": False})
    consumer.subscribe([TOPIC_RAW])
    log.info("lake writer -> %s (flush at %d rows / %.0fs)", LAKE_DIR, FLUSH_ROWS, FLUSH_S)

    rows, bad, last_flush = [], [], time.time()

    def commit_batch():
        nonlocal rows, bad, last_flush
        if rows:
            paths = flush(rows)
            log.info("flushed %d events into %d file(s)", len(rows), len(paths))
        if bad:
            log.warning("quarantined %d unparseable record(s) -> %s", len(bad), quarantine(bad))
        consumer.commit(asynchronous=False)
        rows, bad, last_flush = [], [], time.time()

    try:
        while running:
            for msg in consumer.consume(500, timeout=1.0):
                if msg.error():
                    raise KafkaException(msg.error())
                try:
                    rows.append(to_row(msg.value(), msg.partition(), msg.offset()))
                except (ValueError, KeyError, TypeError) as exc:
                    # ingest validates, so this is rare; keep it anyway (the processor also DLQs it)
                    bad.append(bad_record(msg.value(), msg.partition(), msg.offset(), exc))
            pending = len(rows) + len(bad)
            if len(rows) >= FLUSH_ROWS or (pending and time.time() - last_flush >= FLUSH_S):
                commit_batch()
    finally:
        if rows or bad:
            commit_batch()
        consumer.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
