"""Warehouse writer (FR3): stream-processor outputs -> PostgreSQL.

A separate consumer of the processor's output topics, so the processor keeps one job.
  security.alerts            -> alerts (upsert on alert_id) + incident correlation
  security.aggregates        -> aggregates (upsert on window_start, source_type)
  security.pipeline.metrics  -> pipeline_metrics
  security.sim.campaigns     -> campaigns (ground truth, for the scoreboard only)

Delivery: at-least-once. Kafka offsets are committed only after the DB transaction
commits, and every write is an idempotent upsert, so a replay changes nothing.

Bad messages: each message is written inside its own savepoint. One that cannot be
stored (bad JSON, missing field, a value Postgres rejects) is rolled back alone and
recorded in warehouse_rejects with its Kafka coordinates; the rest of the batch commits.
Without this, one poison message would crash the writer again on every restart.
Connection or schema errors are not "bad messages": they still stop the writer.

Schema: warehouse/schema.sql is idempotent and applied at startup, so new tables and
views reach an existing database without a manual migration step.

Incidents: alerts from the same attacker are chained while they keep arriving less than
INCIDENT_GAP apart (a session window). An incident spanning two or more ATT&CK tactics
is a multi-stage intrusion and is raised one severity level.

Run:  python -m warehouse.writer
"""
import json
import logging
import os
import signal
import uuid
from pathlib import Path

import psycopg
from confluent_kafka import Consumer, KafkaException

from ingest.config import KAFKA_BOOTSTRAP
from processor.config import GROUP_ID, TOPIC_AGGREGATES, TOPIC_ALERTS, TOPIC_METRICS
from processor.rules import SEVERITIES

DSN = os.getenv("WAREHOUSE_DSN", "postgresql://secops:secops@localhost:5432/secops")
TOPIC_CAMPAIGNS = "security.sim.campaigns"
INCIDENT_GAP = "10 minutes"
SCHEMA_SQL = Path(__file__).with_name("schema.sql")

# A message that raises one of these is bad data, not a broken pipeline: reject it, move on.
BAD_MESSAGE = (ValueError, KeyError, TypeError, psycopg.DataError, psycopg.IntegrityError)

log = logging.getLogger("warehouse")
running = True


def incident_entity(a: dict) -> str:
    return a["src_ip"] if a.get("src_ip") else f"user:{a.get('user')}"


def upsert_alert(cur, a: dict) -> None:
    cur.execute("""
        INSERT INTO alerts (alert_id, rule_name, severity, technique, tactic, entity, src_ip, username,
                            dest_ip, window_start, window_end, count, threshold, trigger,
                            first_event_time, last_event_time, first_detected_at, detected_at,
                            detection_latency_ms, sample_event_ids, raw)
        VALUES (%(alert_id)s, %(rule_name)s, %(severity)s, %(technique)s, %(tactic)s, %(entity)s,
                %(src_ip)s, %(user)s, %(dest_ip)s, %(window_start)s, %(window_end)s, %(count)s,
                %(threshold)s, %(trigger)s, %(first_event_time)s, %(event_time)s, %(detected_at)s,
                %(detected_at)s, %(detection_latency_ms)s, %(sample_event_ids)s::uuid[], %(raw)s)
        ON CONFLICT (alert_id) DO UPDATE SET
            severity = EXCLUDED.severity, count = EXCLUDED.count, trigger = EXCLUDED.trigger,
            first_event_time = EXCLUDED.first_event_time, last_event_time = EXCLUDED.last_event_time,
            detected_at = EXCLUDED.detected_at, sample_event_ids = EXCLUDED.sample_event_ids,
            raw = EXCLUDED.raw
        RETURNING incident_id
    """, {**a, "technique": a.get("technique"), "tactic": a.get("tactic"), "raw": json.dumps(a)})
    incident_id = cur.fetchone()[0]

    if incident_id is None:
        entity = incident_entity(a)
        cur.execute("""SELECT incident_id FROM incidents
                       WHERE entity = %s AND last_seen >= %s::timestamptz - %s::interval
                       ORDER BY last_seen DESC LIMIT 1""", (entity, a["first_event_time"], INCIDENT_GAP))
        row = cur.fetchone()
        incident_id = row[0] if row else uuid.uuid4()
        if not row:
            cur.execute("INSERT INTO incidents (incident_id, entity, first_seen, last_seen, severity) "
                        "VALUES (%s, %s, %s, %s, %s)",
                        (incident_id, entity, a["first_event_time"], a["event_time"], a["severity"]))
        cur.execute("UPDATE alerts SET incident_id = %s WHERE alert_id = %s", (incident_id, a["alert_id"]))
    refresh_incident(cur, incident_id)


def refresh_incident(cur, incident_id) -> None:
    """Recompute an incident from its alerts (cheap: a handful of rows)."""
    cur.execute("""SELECT rule_name, tactic, severity, first_event_time, last_event_time
                   FROM alerts WHERE incident_id = %s ORDER BY first_event_time, last_event_time""", (incident_id,))
    rows = cur.fetchall()
    rules, tactics = [], []
    for rule, tactic, *_ in rows:
        if rule not in rules:
            rules.append(rule)
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    level = max(SEVERITIES.index(r[2]) for r in rows)
    if len(tactics) >= 2:
        level = min(level + 1, len(SEVERITIES) - 1)
    # updated_at moves only when the incident's content changes; the summariser keys off it.
    cur.execute("""UPDATE incidents SET first_seen = %(first)s, last_seen = %(last)s,
                       updated_at = CASE WHEN (severity, tactics, rules, alert_count)
                                IS DISTINCT FROM (%(sev)s, %(tactics)s::text[], %(rules)s::text[], %(n)s)
                                THEN now() ELSE updated_at END,
                       severity = %(sev)s, tactics = %(tactics)s, rules = %(rules)s, alert_count = %(n)s
                   WHERE incident_id = %(id)s""",
                {"first": min(r[3] for r in rows), "last": max(r[4] for r in rows), "sev": SEVERITIES[level],
                 "tactics": tactics, "rules": rules, "n": len(rows), "id": incident_id})


def upsert_aggregate(cur, g: dict) -> None:
    cur.execute("""
        INSERT INTO aggregates (window_start, window_end, source_type, event_count, unique_ips,
                                unique_users, success_count, fail_count, denied_count)
        VALUES (%(window_start)s, %(window_end)s, %(source_type)s, %(event_count)s, %(unique_ips)s,
                %(unique_users)s, %(success_count)s, %(fail_count)s, %(denied_count)s)
        ON CONFLICT (window_start, source_type) DO UPDATE SET
            event_count = EXCLUDED.event_count, unique_ips = EXCLUDED.unique_ips,
            unique_users = EXCLUDED.unique_users, success_count = EXCLUDED.success_count,
            fail_count = EXCLUDED.fail_count, denied_count = EXCLUDED.denied_count
    """, g)


def insert_metrics(cur, m: dict) -> None:
    lat = m.get("detection_latency_ms") or {}
    cur.execute("""
        INSERT INTO pipeline_metrics (at, events_per_s, consumer_lag, watermark_delay_s,
                                      latency_p50_ms, latency_p95_ms, latency_p99_ms, raw)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (at) DO NOTHING
    """, (m["at"], m["events_per_s"], m["consumer_lag"], m.get("watermark_delay_s"),
          lat.get("p50"), lat.get("p95"), lat.get("p99"), json.dumps(m)))


def upsert_campaign(cur, c: dict) -> None:
    cur.execute("""
        INSERT INTO campaigns (campaign_id, scenario, attacker_ips, target_user, expected_rules,
                               started_at, ended_at, requests)
        VALUES (%(campaign_id)s, %(scenario)s, %(attacker_ips)s::inet[], %(target_user)s,
                %(expected_rules)s, %(started_at)s, %(ended_at)s, %(requests)s)
        ON CONFLICT (campaign_id) DO UPDATE SET ended_at = EXCLUDED.ended_at, requests = EXCLUDED.requests
    """, c)


def ours(v: dict) -> bool:
    """Ignore outputs of other processor groups (e.g. end-to-end test runs)."""
    return (v.get("processor") or {}).get("group", v.get("group")) == GROUP_ID


HANDLERS = {TOPIC_ALERTS: upsert_alert, TOPIC_AGGREGATES: upsert_aggregate,
            TOPIC_METRICS: insert_metrics, TOPIC_CAMPAIGNS: upsert_campaign}

# The fields each handler's SQL reads (a value may be null, the key must be there).
# Checked up front, so a message missing one is rejected as bad data instead of
# failing inside psycopg as a ProgrammingError, which also covers real bugs.
REQUIRED = {
    TOPIC_ALERTS: ("alert_id", "rule_name", "severity", "entity", "src_ip", "user", "dest_ip",
                   "window_start", "window_end", "count", "threshold", "trigger", "first_event_time",
                   "event_time", "detected_at", "detection_latency_ms", "sample_event_ids"),
    TOPIC_AGGREGATES: ("window_start", "window_end", "source_type", "event_count", "unique_ips",
                       "unique_users", "success_count", "fail_count", "denied_count"),
    TOPIC_METRICS: ("at", "events_per_s", "consumer_lag"),
    TOPIC_CAMPAIGNS: ("campaign_id", "scenario", "attacker_ips", "target_user", "expected_rules",
                      "started_at", "ended_at", "requests"),
}


def apply_schema(conn) -> None:
    conn.execute(SCHEMA_SQL.read_text(encoding="utf-8"))


def check_fields(topic: str, v) -> None:
    if not isinstance(v, dict):
        raise TypeError(f"expected a JSON object, got {type(v).__name__}")
    missing = [f for f in REQUIRED[topic] if f not in v]
    if missing:
        raise KeyError(f"missing field(s): {', '.join(missing)}")


def store(conn, cur, topic: str, partition: int, offset: int, value: bytes) -> bool:
    """Write one message inside its own savepoint. Returns False if it was rejected."""
    try:
        with conn.transaction():
            v = json.loads(value)
            if topic == TOPIC_CAMPAIGNS or ours(v):
                check_fields(topic, v)
                HANDLERS[topic](cur, v)
        return True
    except BAD_MESSAGE as exc:
        log.warning("rejected %s[%d]@%d: %s", topic, partition, offset, exc)
        cur.execute("""INSERT INTO warehouse_rejects (topic, partition, "offset", error, payload)
                       VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                    (topic, partition, offset, f"{type(exc).__name__}: {exc}",
                     value.decode("utf-8", errors="replace") if value is not None else None))
        return False


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    signal.signal(signal.SIGINT, lambda *_: globals().update(running=False))
    signal.signal(signal.SIGTERM, lambda *_: globals().update(running=False))

    consumer = Consumer({"bootstrap.servers": KAFKA_BOOTSTRAP, "group.id": "warehouse-writer-v1",
                         "auto.offset.reset": "earliest", "enable.auto.commit": False})
    consumer.subscribe(list(HANDLERS))
    log.info("warehouse writer -> %s", DSN.rsplit("@", 1)[-1])
    with psycopg.connect(DSN, autocommit=True) as conn:
        apply_schema(conn)
        try:
            while running:
                msgs = consumer.consume(500, timeout=1.0)
                if not msgs:
                    continue
                with conn.transaction(), conn.cursor() as cur:
                    for msg in msgs:
                        if msg.error():
                            raise KafkaException(msg.error())
                        store(conn, cur, msg.topic(), msg.partition(), msg.offset(), msg.value())
                consumer.commit(asynchronous=False)
        finally:
            consumer.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
