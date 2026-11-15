"""Blue team: SOC dashboard API (port 8003), serving dashboard/ui.

Two access paths, matching what each view needs (and Lab 2's FR5 risk, "frequent auto
polling slowing backend analytical queries"):
  live     alerts + pipeline metrics are PUSHED over a WebSocket straight from Kafka
  history  incidents, scoreboard, charts and storage stats are SQL over the warehouse

Run:  uvicorn dashboard.api:app --port 8003
"""
import asyncio
import json
import logging
import os
import threading
import uuid
from contextlib import asynccontextmanager

import psycopg
from confluent_kafka import Consumer
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from psycopg.rows import dict_row

from ingest.config import KAFKA_BOOTSTRAP
from processor.config import GROUP_ID, TOPIC_ALERTS, TOPIC_METRICS

from . import pipeline, scoring, summariser

DSN = os.getenv("WAREHOUSE_DSN", "postgresql://secops:secops@localhost:5432/secops")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
sockets: set[WebSocket] = set()
health: dict = {}               # latest pipeline.collect(), refreshed every 5 s by one task
log = logging.getLogger("dashboard")


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
    stop = threading.Event()
    threading.Thread(target=kafka_bridge, args=(asyncio.get_running_loop(), stop), daemon=True).start()
    tasks = [asyncio.create_task(summariser.run()), asyncio.create_task(collect_health())]
    yield
    stop.set()
    for t in tasks:
        t.cancel()


async def collect_health() -> None:
    while True:
        try:
            m = await query("SELECT raw FROM pipeline_metrics ORDER BY at DESC LIMIT 1")
            d = await query("SELECT avg(extract(epoch FROM ingested_at - at)) s FROM pipeline_metrics "
                            "WHERE at > now() - interval '1 minute'")
            health.update(await asyncio.to_thread(pipeline.collect, m[0]["raw"] if m else None, d[0]["s"]))
        except Exception as exc:
            log.warning("pipeline health: %s", exc)
        await asyncio.sleep(5)


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
    async with await psycopg.AsyncConnection.connect(DSN, row_factory=dict_row) as conn:
        return await (await conn.execute(sql, params)).fetchall()


def alert_view(r: dict) -> dict:
    a = r["raw"]
    a["incident_id"] = str(r["incident_id"]) if r["incident_id"] else None
    a["first_detected_at"] = r["first_detected_at"]       # older alerts predate the field
    return a


def incident_view(r: dict) -> dict:
    return {"incident_id": str(r["incident_id"]), "entity": r["entity"], "first_seen": r["first_seen"],
            "last_seen": r["last_seen"], "severity": r["severity"], "tactics": r["tactics"],
            "rules": r["rules"], "alert_count": r["alert_count"], "multi_stage": len(r["tactics"]) >= 2,
            "summary": r["summary"], "summary_source": r["summary_source"]}


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
            "lake": {k: (health.get("storage") or {}).get(f"lake_{k}", 0) for k in ("files", "rows")}
                    | {"bytes": (health.get("storage") or {}).get("parquet_bytes", 0)},
            "warehouse": counts}


@app.get("/api/pipeline")
async def pipeline_health():
    return health or {"reconciliation": None, "tiers": [], "storage": None}


@app.get("/api/metrics")
async def metrics(minutes: int = 15):
    rows = await query("SELECT raw FROM pipeline_metrics WHERE at > now() - make_interval(mins => %s) "
                       "ORDER BY at", (minutes,))
    return [r["raw"] for r in rows]


@app.get("/api/alerts")
async def alerts(limit: int = 100):
    rows = await query("SELECT raw, incident_id, first_detected_at FROM alerts ORDER BY first_detected_at DESC LIMIT %s", (limit,))
    return [alert_view(r) for r in rows]


@app.get("/api/incidents")
async def incidents(limit: int = 50):
    return [incident_view(r) for r in await query("SELECT * FROM incidents ORDER BY last_seen DESC LIMIT %s", (limit,))]


@app.get("/api/incidents/{incident_id}")
async def incident(incident_id: uuid.UUID):
    rows = await query("SELECT * FROM incidents WHERE incident_id = %s", (incident_id,))
    if not rows:
        raise HTTPException(404, "no such incident")
    alerts_ = await query("SELECT raw, incident_id, first_detected_at FROM alerts WHERE incident_id = %s ORDER BY first_event_time",
                          (incident_id,))
    return {**incident_view(rows[0]), "alerts": [alert_view(a) for a in alerts_]}


@app.get("/api/aggregates")
async def aggregates(minutes: int = 30):
    return await query("SELECT * FROM aggregates WHERE window_start > now() - make_interval(mins => %s) "
                       "ORDER BY window_start, source_type", (minutes,))


@app.get("/api/scoreboard")
async def scoreboard():
    camps = await query("SELECT campaign_id, scenario, malicious, ARRAY(SELECT host(x) FROM unnest(attacker_ips) x) ips, "
                        "target_user, expected_rules, started_at, ended_at, requests FROM campaigns ORDER BY started_at DESC")
    since = min((c["started_at"] for c in camps), default=None)
    rows = await query("SELECT raw, incident_id, rule_name, host(src_ip) src_ip, username, first_detected_at, window_end "
                       "FROM alerts WHERE %s::timestamptz IS NULL OR first_detected_at >= %s::timestamptz - interval '1 minute'",
                       (since, since))
    alerts_ = [{**r, "view": alert_view(dict(r, raw=dict(r["raw"])))} for r in rows]
    newest = max((f["newest_event"] for f in pipeline.lake_files() if f["newest_event"]), default=None)
    events_total = (health.get("reconciliation") or {}).get("in_kafka", 0)
    return await asyncio.to_thread(scoring.score, camps, alerts_, newest, events_total)
