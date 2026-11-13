"""Read the data lake: raw events by time range, with duplicates removed.

The writer is at-least-once, so the same event_id can sit in the lake twice. Every
read here drops those duplicates, so callers never have to think about it.

Only the hour folders that overlap the requested range are opened (partition
pruning by folder name); inside each file, Parquet min/max statistics skip the rest.

    from lake import reader
    t = reader.read_events(since, until, src_ip="127.66.0.5")   # -> pyarrow.Table
    t = reader.events_by_id(alert["sample_event_ids"], alert["first_event_time"], alert["last_event_time"])

Run:  python -m lake.reader --minutes 60 [--src-ip IP] [--source-type auth|network|api]
"""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.dataset as ds

from lake.writer import LAKE_DIR, SCHEMA


def hour_dirs(since: datetime, until: datetime, lake_dir: Path = LAKE_DIR) -> list[Path]:
    """The year=/month=/day=/hour= folders whose hour overlaps [since, until]."""
    first = since.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    out = []
    for folder in sorted(lake_dir.glob("year=*/month=*/day=*/hour=*")):
        y, m, d, h = (int(p.split("=")[1]) for p in folder.parts[-4:])
        if first <= datetime(y, m, d, h, tzinfo=timezone.utc) <= until:
            out.append(folder)
    return out


def dedup(table: pa.Table) -> pa.Table:
    """Keep the first copy of each event_id (the writer may have stored one twice)."""
    seen, keep = set(), []
    for i, event_id in enumerate(table.column("event_id").to_pylist()):
        if event_id not in seen:
            seen.add(event_id)
            keep.append(i)
    return table if len(keep) == table.num_rows else table.take(keep)


def read_events(since: datetime, until: datetime, src_ip: str = None, source_type: str = None,
                lake_dir: Path = LAKE_DIR) -> pa.Table:
    """Events with since <= event_time <= until, oldest first, optionally for one IP / source."""
    files = [f for d in hour_dirs(since, until, lake_dir) for f in d.glob("*.parquet")]
    if not files:
        return SCHEMA.empty_table()
    where = (ds.field("event_time") >= pa.scalar(since, pa.timestamp("us", tz="UTC"))) & \
            (ds.field("event_time") <= pa.scalar(until, pa.timestamp("us", tz="UTC")))
    if src_ip:
        where &= ds.field("src_ip") == src_ip
    if source_type:
        where &= ds.field("source_type") == source_type
    table = ds.dataset(files, schema=SCHEMA, format="parquet").to_table(filter=where)
    return dedup(table.sort_by([("event_time", "ascending"), ("kafka_partition", "ascending"),
                                ("kafka_offset", "ascending")]))


def events_by_id(event_ids: list, since, until, lake_dir: Path = LAKE_DIR) -> pa.Table:
    """Provenance: the raw events behind an alert (its sample_event_ids and time span)."""
    since, until = _as_dt(since), _as_dt(until)
    table = read_events(since, until, lake_dir=lake_dir)
    return table.filter(pc.is_in(table.column("event_id"), pa.array([str(e) for e in event_ids])))


def _as_dt(t) -> datetime:
    return t if isinstance(t, datetime) else datetime.fromisoformat(t)


def main() -> int:
    ap = argparse.ArgumentParser(description="Query raw events from the Parquet lake.")
    ap.add_argument("--minutes", type=int, default=60, help="look back this far (default 60)")
    ap.add_argument("--src-ip")
    ap.add_argument("--source-type", choices=["auth", "network", "api"])
    ap.add_argument("--rows", type=int, default=20, help="rows to print (default 20)")
    args = ap.parse_args()

    until = datetime.now(timezone.utc)
    t = read_events(until - timedelta(minutes=args.minutes), until, args.src_ip, args.source_type)
    print(f"{t.num_rows} event(s) in the last {args.minutes} min")
    for r in t.slice(max(0, t.num_rows - args.rows)).to_pylist():
        print(f"  {r['event_time']:%H:%M:%S}  {r['source_type']:<7} {r['src_ip']:<15} "
              f"{r['dest_ip_port'] or '-':<21} {r['user'] or '-':<10} {r['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
