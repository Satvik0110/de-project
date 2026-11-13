"""Blue team: SOC dashboard API (port 8003), serving dashboard/ui.

Two access paths, matching what each view needs (and Lab 2's FR5 risk, "frequent auto
polling slowing backend analytical queries"):
  live     alerts + pipeline metrics are PUSHED over a WebSocket straight from Kafka
  history  incidents, scoreboard, charts and storage stats are SQL over the warehouse
  raw      the events behind an alert are read back from the Parquet lake (provenance)

SQL runs on a small connection pool, opened once at startup: the UI polls several
endpoints every few seconds, and a fresh Postgres connection per query would cost more
than the query itself.

Run:  uvicorn dashboard.api:app --port 8003
"""
import asyncio
import json
import logging
import os
import statistics
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyarrow.parquet as pq
from confluent_kafka import Consumer
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from ingest.config import KAFKA_BOOTSTRAP
from lake import reader as lake_reader
from lake.writer import LAKE_DIR
from processor.config import GROUP_ID, TOPIC_ALERTS, TOPIC_METRICS

from . import summariser

DSN = os.getenv("WAREHOUSE_DSN", "postgresql://secops:secops@localhost:5432/secops")
GRACE = timedelta(seconds=120)   # an alert counts for a campaign if raised up to this long after it ended
pool: AsyncConnectionPool = None  # opened in lifespan()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
sockets: set[WebSocket] = set()


# ------------------------------------------------------------------ live bridge

def kafka_bridge(loop: asyncio.AbstractEventLoop, stop: threading.Event) -> None:
    """One consumer on one thread (confluent_kafka consumers are not thread-safe)."""
    c = Consumer({"bootstrap.servers": KAFKA_BOOTSTRAP, "group.id": f"dashboard-{uuid.uuid4().hex[:8]}",
                  "auto.offset.reset": "latest", "enable.auto.commit": False})
    c.subscribe([TOPIC_ALERTS, TOPIC_METRICS])
    try:
        while not stop.is_set():
            msg = c.poll(0.5)
            if msg is None or msg.error():
                continue
            v = json.loads(msg.value())
            if (v.get("processor") or {}).get("group", v.get("group")) != GROUP_ID:
                continue
            kind = "alert" if msg.topic() == TOPIC_ALERTS else "metrics"
            asyncio.run_coroutine_threadsafe(broadcast({"type": kind, kind: v}), loop)
    finally:
        c.close()


async def broadcast(msg: dict) -> None:
    for ws in list(sockets):
        try:
            await ws.send_json(msg)
        except Exception:
            sockets.discard(ws)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    # open() does not wait for a connection: the API starts even if Postgres is still
    # coming up, and queries wait until the pool has one.
    pool = AsyncConnectionPool(DSN, min_size=1, max_size=5, open=False, kwargs={"row_factory": dict_row})
    await pool.open()
    stop = threading.Event()
    threading.Thread(target=kafka_bridge, args=(asyncio.get_running_loop(), stop), daemon=True).start()
    task = asyncio.create_task(summariser.run())
    yield
    stop.set()
    task.cancel()
    await pool.close()


app = FastAPI(title="SOC dashboard API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.websocket("/ws/live")
async def live(ws: WebSocket):
    await ws.accept()
    sockets.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        sockets.discard(ws)


# ------------------------------------------------------------------ queries

async def query(sql: str, params=()) -> list[dict]:
    async with pool.connection() as conn:
        return await (await conn.execute(sql, params)).fetchall()


def alert_view(r: dict) -> dict:
    a = r["raw"]
    a["incident_id"] = str(r["incident_id"]) if r["incident_id"] else None
    return a


def incident_view(r: dict) -> dict:
    return {"incident_id": str(r["incident_id"]), "entity": r["entity"], "first_seen": r["first_seen"],
            "last_seen": r["last_seen"], "severity": r["severity"], "tactics": r["tactics"],
            "rules": r["rules"], "alert_count": r["alert_count"], "multi_stage": len(r["tactics"]) >= 2,
            "summary": r["summary"], "summary_source": r["summary_source"]}


_lake_rows: dict[str, int] = {}   # parquet files are immutable: read each footer once


def lake_stats() -> dict:
    files = list(Path(LAKE_DIR).rglob("*.parquet"))
    for f in files:
        if str(f) not in _lake_rows:
            _lake_rows[str(f)] = pq.read_metadata(f).num_rows
    for gone in _lake_rows.keys() - {str(f) for f in files}:   # removed by lake.compact
        del _lake_rows[gone]
    return {"files": len(files), "bytes": sum(f.stat().st_size for f in files),
            "rows": sum(_lake_rows[str(f)] for f in files)}


@app.get("/api/summary")
async def summary():
    metrics = await query("SELECT raw FROM pipeline_metrics ORDER BY at DESC LIMIT 1")
    sev = await query("SELECT severity, count(*) n FROM alerts GROUP BY severity")
    rule = await query("SELECT rule_name, count(*) n FROM alerts GROUP BY rule_name")
    inc = await query("SELECT count(*) total, count(*) FILTER (WHERE cardinality(tactics) >= 2) multi FROM incidents")
    counts = (await query("""SELECT (SELECT count(*) FROM alerts) alerts, (SELECT count(*) FROM incidents) incidents,
                                    (SELECT count(*) FROM aggregates) aggregates,
                                    (SELECT count(*) FROM campaigns) campaigns"""))[0]
    return {"metrics": metrics[0]["raw"] if metrics else None,
            "alerts_by_severity": {r["severity"]: r["n"] for r in sev},
            "alerts_by_rule": {r["rule_name"]: r["n"] for r in rule},
            "incidents": {"total": inc[0]["total"], "multi_stage": inc[0]["multi"]},
            "lake": await asyncio.to_thread(lake_stats), "warehouse": counts}


@app.get("/api/health")
async def health():
    """Is the warehouse reachable, and how far behind is the newest metrics snapshot?"""
    try:
        row = (await query("SELECT now() - max(at) AS age FROM pipeline_metrics"))[0]
    except Exception as exc:
        return {"warehouse": "down", "error": str(exc)}
    age = row["age"].total_seconds() if row["age"] is not None else None
    return {"warehouse": "up", "metrics_age_s": age, "lake_dir": str(LAKE_DIR),
            "lake_exists": Path(LAKE_DIR).exists()}


@app.get("/api/metrics")
async def metrics(minutes: int = Query(15, ge=1, le=24 * 60)):
    rows = await query("SELECT raw FROM pipeline_metrics WHERE at > now() - make_interval(mins => %s) "
                       "ORDER BY at", (minutes,))
    return [r["raw"] for r in rows]


@app.get("/api/alerts")
async def alerts(limit: int = Query(100, ge=1, le=1000)):
    rows = await query("SELECT raw, incident_id FROM alerts ORDER BY first_detected_at DESC LIMIT %s", (limit,))
    return [alert_view(r) for r in rows]


@app.get("/api/alerts/{alert_id}/events")
async def alert_events(alert_id: uuid.UUID):
    """Provenance: the raw events behind an alert, read back from the Parquet lake.

    Uses the alert's sample_event_ids and its first/last event time, so only the hour
    folders that alert spans are opened. Events still in the lake writer's buffer (up to
    30 s) are not on disk yet; `missing` lists those ids.
    """
    rows = await query("SELECT sample_event_ids, first_event_time, last_event_time FROM alerts "
                       "WHERE alert_id = %s", (alert_id,))
    if not rows:
        raise HTTPException(404, "no such alert")
    a = rows[0]
    ids = [str(i) for i in a["sample_event_ids"]]
    table = await asyncio.to_thread(lake_reader.events_by_id, ids, a["first_event_time"], a["last_event_time"],
                                    LAKE_DIR)
    events = table.to_pylist()
    found = {e["event_id"] for e in events}
    return {"alert_id": str(alert_id), "events": events, "missing": [i for i in ids if i not in found]}


@app.get("/api/threat-actors")
async def threat_actors(minutes: int = Query(60, ge=1, le=7 * 24 * 60), limit: int = Query(50, ge=1, le=500)):
    """Attackers seen in the last `minutes`, worst first (warehouse view threat_actors)."""
    return await query("SELECT * FROM threat_actors WHERE last_seen > now() - make_interval(mins => %s) "
                       "ORDER BY severity_rank(severity) DESC, last_seen DESC LIMIT %s", (minutes, limit))


@app.get("/api/attack-types")
async def attack_types():
    """Per detection rule: volume, distinct attackers, latency (warehouse view attack_type_breakdown)."""
    return await query("SELECT * FROM attack_type_breakdown ORDER BY alerts DESC")


@app.get("/api/ip-stats")
async def ip_stats(hours: int = Query(24, ge=1, le=24 * 30), limit: int = Query(100, ge=1, le=1000)):
    """Per attacker IP per hour (warehouse view hourly_ip_stats)."""
    return await query("SELECT * FROM hourly_ip_stats WHERE hour > now() - make_interval(hours => %s) "
                       "ORDER BY hour DESC, alerts DESC LIMIT %s", (hours, limit))


@app.get("/api/incidents")
async def incidents(limit: int = Query(50, ge=1, le=500)):
    return [incident_view(r) for r in await query("SELECT * FROM incidents ORDER BY last_seen DESC LIMIT %s", (limit,))]


@app.get("/api/incidents/{incident_id}")
async def incident(incident_id: uuid.UUID):
    rows = await query("SELECT * FROM incidents WHERE incident_id = %s", (incident_id,))
    if not rows:
        raise HTTPException(404, "no such incident")
    alerts_ = await query("SELECT raw, incident_id FROM alerts WHERE incident_id = %s ORDER BY first_event_time",
                          (incident_id,))
    return {**incident_view(rows[0]), "alerts": [alert_view(a) for a in alerts_]}


@app.get("/api/aggregates")
async def aggregates(minutes: int = Query(30, ge=1, le=24 * 60)):
    return await query("SELECT * FROM aggregates WHERE window_start > now() - make_interval(mins => %s) "
                       "ORDER BY window_start, source_type", (minutes,))


@app.get("/api/scoreboard")
async def scoreboard():
    """Grade detection against the simulator's ground truth.

    A campaign's expected rule is detected if an alert for that rule names one of the
    campaign's attacker IPs (or its target account, for per-user rules) and was raised
    between the campaign start and DETECT_GRACE_S after its end. Time-to-detect is the
    first such alert's detection time minus the campaign start. An alert that matches
    no campaign at all came from benign traffic: a false positive.
    """
    camps = await query("SELECT campaign_id, scenario, ARRAY(SELECT host(x) FROM unnest(attacker_ips) x) ips, target_user, expected_rules, "
                        "started_at, ended_at FROM campaigns ORDER BY started_at DESC")
    since = min((c["started_at"] for c in camps), default=None)
    alerts_ = await query("SELECT raw, incident_id, rule_name, host(src_ip) src_ip, username, first_detected_at "
                          "FROM alerts WHERE %s::timestamptz IS NULL OR first_detected_at >= %s - interval '1 minute'",
                          (since, since))
    attributed: set = set()
    out = []
    now = datetime.now(timezone.utc)
    for c in camps:
        ips = set(c["ips"])
        end = c["ended_at"] or now            # still running
        hits = [a for a in alerts_
                if (a["src_ip"] in ips or (a["src_ip"] is None and a["username"] == c["target_user"]))
                and c["started_at"] <= a["first_detected_at"] <= end + GRACE]
        attributed.update(id(a) for a in hits)
        expected = c["expected_rules"]
        detected = sorted({a["rule_name"] for a in hits} & set(expected))
        first = min((a["first_detected_at"] for a in hits if a["rule_name"] in expected), default=None)
        out.append({"campaign_id": str(c["campaign_id"]), "scenario": c["scenario"], "started_at": c["started_at"],
                    "ended_at": c["ended_at"], "attacker_ips": c["ips"], "expected_rules": expected,
                    "detected_rules": detected, "missed_rules": [r for r in expected if r not in detected],
                    "detected": bool(detected),
                    "ttd_ms": round((first - c["started_at"]).total_seconds() * 1000) if first else None})

    by = {}
    for c in out:
        by.setdefault(c["scenario"], []).append(c)
    by_scenario = [{"scenario": s, "campaigns": len(cs), "detected": sum(c["detected"] for c in cs),
                    "detection_rate": sum(c["detected"] for c in cs) / len(cs),
                    "median_ttd_ms": _median([c["ttd_ms"] for c in cs])} for s, cs in by.items()]
    fps = [a for a in alerts_ if id(a) not in attributed]
    expected_n = sum(len(c["expected_rules"]) for c in out)
    return {"campaigns": out[:50], "by_scenario": by_scenario, "alerts_total": len(alerts_),
            "true_positive_alerts": len(alerts_) - len(fps), "false_positive_alerts": len(fps),
            "precision": (len(alerts_) - len(fps)) / len(alerts_) if alerts_ else None,
            "recall": sum(len(c["detected_rules"]) for c in out) / expected_n if expected_n else None,
            "median_ttd_ms": _median([c["ttd_ms"] for c in out]),
            "false_positives": [alert_view(a) for a in fps[:50]]}


def _median(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None
