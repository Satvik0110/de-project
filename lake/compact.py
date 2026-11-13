"""Lake compaction: merge each finished hour's small files into one, without duplicates.

The writer flushes every 30 s, so a busy hour holds ~120 small files. Many small files
make every scan slower (one open + footer read per file). Once an hour is SETTLE_MIN
minutes in the past, this merges its files into a single file sorted by event_time,
keeping one copy per event_id.

Safe to run while the writer is running:
  - it only deletes the files it read; a late event written meanwhile is a new file
    that the next run picks up
  - the merged file is written to a temporary name and renamed into place, like the writer
  - a crash after the rename but before the deletes leaves duplicates for a moment,
    which readers drop anyway and the next run removes

Run:  python -m lake.compact [--settle-min 15] [--dry-run]
"""
import argparse
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyarrow.parquet as pq

from lake.reader import dedup
from lake.writer import LAKE_DIR, SCHEMA

SETTLE_MIN = int(os.getenv("LAKE_COMPACT_SETTLE_MIN", "15"))

log = logging.getLogger("lake.compact")


def hour_start(folder: Path) -> datetime:
    y, m, d, h = (int(p.split("=")[1]) for p in folder.parts[-4:])
    return datetime(y, m, d, h, tzinfo=timezone.utc)


def compact_hour(folder: Path) -> tuple[int, int, int]:
    """Merge one hour folder. Returns (files merged, rows read, rows kept)."""
    files = sorted(folder.glob("*.parquet"))
    if len(files) < 2:
        return 0, 0, 0
    table = pq.read_table(files, schema=SCHEMA)
    merged = dedup(table.sort_by([("event_time", "ascending"), ("kafka_partition", "ascending"),
                                  ("kafka_offset", "ascending")]))
    path = folder / f"compacted-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}.parquet"
    tmp = path.with_suffix(".tmp")
    pq.write_table(merged, tmp, compression="snappy")
    tmp.rename(path)
    for f in files:
        f.unlink()
    return len(files), table.num_rows, merged.num_rows


def compact(lake_dir: Path = LAKE_DIR, settle_min: int = SETTLE_MIN, dry_run: bool = False) -> list[dict]:
    """Compact every hour that ended at least settle_min minutes ago."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settle_min)
    report = []
    for folder in sorted(lake_dir.glob("year=*/month=*/day=*/hour=*")):
        if hour_start(folder) + timedelta(hours=1) > cutoff:
            continue                                   # hour still open (or just closed)
        n_files = len(list(folder.glob("*.parquet")))
        if n_files < 2:
            continue
        if dry_run:
            report.append({"hour": folder.relative_to(lake_dir).as_posix(), "files": n_files})
            continue
        files, read, kept = compact_hour(folder)
        report.append({"hour": folder.relative_to(lake_dir).as_posix(), "files": files,
                       "rows": read, "duplicates_removed": read - kept})
    return report


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(description="Merge each finished hour of the lake into one file.")
    ap.add_argument("--settle-min", type=int, default=SETTLE_MIN,
                    help=f"only hours that ended this many minutes ago (default {SETTLE_MIN})")
    ap.add_argument("--dry-run", action="store_true", help="list what would be compacted")
    args = ap.parse_args()

    report = compact(settle_min=args.settle_min, dry_run=args.dry_run)
    for r in report:
        log.info("%s %s", "would compact" if args.dry_run else "compacted", r)
    log.info("%d hour(s) %s", len(report), "to compact" if args.dry_run else "compacted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
