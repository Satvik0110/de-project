"""Unit tests for the data lake: writer, reader and compaction. No Kafka needed.

    python -m pytest tests/test_lake.py -v
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pyarrow.parquet as pq
import pytest

from lake import compact, reader, writer

T0 = datetime(2026, 11, 10, 14, 0, tzinfo=timezone.utc)


def raw(t: datetime, ip="127.66.0.5", eid=None, status="fail") -> bytes:
    """One event exactly as ingest puts it on security.events.raw."""
    return json.dumps({
        "schema_version": 1, "event_id": eid or str(uuid.uuid4()),
        "event_time": t.isoformat().replace("+00:00", "Z"), "ingest_time": t.isoformat(),
        "source_type": "auth", "src_ip": ip, "dest_ip_port": "127.0.10.1:8002",
        "user": "admin", "status": status, "raw_payload": {"endpoint": "/login"},
    }).encode()


def rows(*times, **kw):
    return [writer.to_row(raw(t, **kw), partition=0, offset=i) for i, t in enumerate(times)]


# ------------------------------------------------------------------ writer

def test_to_row_keeps_contract_and_provenance():
    r = writer.to_row(raw(T0), partition=2, offset=41)
    assert r["event_time"] == T0 and r["status"] == "fail"
    assert json.loads(r["raw_payload"]) == {"endpoint": "/login"}       # free-form kept as JSON text
    assert (r["kafka_partition"], r["kafka_offset"]) == (2, 41)


@pytest.mark.parametrize("bad", [b"not json", b'{"event_id": "x"}', b'{"event_time": 5}'])
def test_to_row_rejects_malformed(bad):
    with pytest.raises((ValueError, KeyError, TypeError)):
        writer.to_row(bad, 0, 0)


def test_flush_partitions_by_event_time(tmp_path):
    late = T0 - timedelta(hours=3)                 # a late event lands in its true hour
    paths = writer.flush(rows(T0, T0 + timedelta(minutes=5), late), lake_dir=tmp_path)
    dirs = sorted(p.parent.relative_to(tmp_path).as_posix() for p in paths)
    assert dirs == ["year=2026/month=11/day=10/hour=11", "year=2026/month=11/day=10/hour=14"]
    assert sum(pq.read_metadata(p).num_rows for p in paths) == 3
    assert not list(tmp_path.rglob("*.tmp"))       # no half-written files left behind
    assert pq.read_metadata(paths[0]).row_group(0).column(0).compression == "SNAPPY"


def test_quarantine_keeps_bad_records_out_of_parquet(tmp_path):
    rec = writer.bad_record(b"\xffnot json", 1, 7, ValueError("boom"))
    path = writer.quarantine([rec], lake_dir=tmp_path)
    saved = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert (saved["kafka_partition"], saved["kafka_offset"]) == (1, 7) and "boom" in saved["error"]
    writer.flush(rows(T0), lake_dir=tmp_path)
    assert reader.read_events(T0, T0, lake_dir=tmp_path).num_rows == 1     # _quarantine is ignored


# ------------------------------------------------------------------ reader

def test_read_events_dedups_and_filters(tmp_path):
    eid = str(uuid.uuid4())
    writer.flush(rows(T0, eid=eid), lake_dir=tmp_path)
    writer.flush(rows(T0, eid=eid), lake_dir=tmp_path)                    # replayed after a crash
    writer.flush(rows(T0 + timedelta(minutes=1), ip="127.0.1.9"), lake_dir=tmp_path)
    end = T0 + timedelta(hours=1)

    assert reader.read_events(T0, end, lake_dir=tmp_path).num_rows == 2
    only = reader.read_events(T0, end, src_ip="127.0.1.9", lake_dir=tmp_path)
    assert only.column("src_ip").to_pylist() == ["127.0.1.9"]
    assert reader.read_events(T0 - timedelta(hours=5), T0 - timedelta(hours=4), lake_dir=tmp_path).num_rows == 0


def test_read_events_opens_only_overlapping_hours(tmp_path):
    writer.flush(rows(T0, T0 + timedelta(hours=1), T0 + timedelta(hours=2)), lake_dir=tmp_path)
    dirs = reader.hour_dirs(T0 + timedelta(minutes=30), T0 + timedelta(hours=1, minutes=10), tmp_path)
    assert [d.name for d in dirs] == ["hour=14", "hour=15"]


def test_events_by_id_traces_an_alert(tmp_path):
    batch = rows(*(T0 + timedelta(seconds=s) for s in range(10)))
    writer.flush(batch, lake_dir=tmp_path)
    wanted = [batch[2]["event_id"], batch[7]["event_id"]]
    t = reader.events_by_id(wanted, T0.isoformat(), (T0 + timedelta(seconds=9)).isoformat(), lake_dir=tmp_path)
    assert sorted(t.column("event_id").to_pylist()) == sorted(wanted)


def test_empty_lake(tmp_path):
    assert reader.read_events(T0, T0 + timedelta(hours=1), lake_dir=tmp_path).num_rows == 0


# ------------------------------------------------------------------ compaction

def test_compact_merges_finished_hours_and_drops_duplicates(tmp_path):
    eid = str(uuid.uuid4())
    for t in (T0, T0 + timedelta(minutes=10), T0 + timedelta(minutes=20)):
        writer.flush(rows(t), lake_dir=tmp_path)
    writer.flush(rows(T0, eid=eid) + rows(T0, eid=eid), lake_dir=tmp_path)  # duplicate pair

    report = compact.compact(lake_dir=tmp_path, settle_min=15)
    assert report == [{"hour": "year=2026/month=11/day=10/hour=14", "files": 4, "rows": 5,
                       "duplicates_removed": 1}]
    files = list(tmp_path.rglob("*.parquet"))
    assert len(files) == 1 and pq.read_metadata(files[0]).num_rows == 4
    times = pq.read_table(files[0]).column("event_time").to_pylist()
    assert times == sorted(times)


def test_compact_leaves_the_current_hour_alone(tmp_path):
    now = datetime.now(timezone.utc)
    writer.flush(rows(now), lake_dir=tmp_path)
    writer.flush(rows(now), lake_dir=tmp_path)
    assert compact.compact(lake_dir=tmp_path) == []
    assert len(list(tmp_path.rglob("*.parquet"))) == 2


def test_compact_dry_run_changes_nothing(tmp_path):
    writer.flush(rows(T0), lake_dir=tmp_path)
    writer.flush(rows(T0), lake_dir=tmp_path)
    assert compact.compact(lake_dir=tmp_path, dry_run=True)[0]["files"] == 2
    assert len(list(tmp_path.rglob("*.parquet"))) == 2
