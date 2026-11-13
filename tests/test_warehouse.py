"""Warehouse writer tests against a real PostgreSQL. No Kafka needed.

Each run uses its own throwaway Postgres schema, so the demo data in public is untouched.
Skipped when no database is reachable (start one with `docker compose up -d postgres`).

    python -m pytest tests/test_warehouse.py -v
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from processor.config import GROUP_ID, TOPIC_AGGREGATES, TOPIC_ALERTS, TOPIC_METRICS
from warehouse import writer

T0 = datetime(2026, 11, 10, 14, 0, tzinfo=timezone.utc)
ATTACKER = "127.66.0.5"


@pytest.fixture
def db():
    try:
        conn = psycopg.connect(writer.DSN, autocommit=True, connect_timeout=3)
    except psycopg.OperationalError as exc:
        pytest.skip(f"no PostgreSQL at {writer.DSN.rsplit('@', 1)[-1]}: {exc}")
    schema = f"test_{uuid.uuid4().hex[:8]}"
    conn.execute(f"CREATE SCHEMA {schema}")
    conn.execute(f"SET search_path TO {schema}")
    writer.apply_schema(conn)
    try:
        yield conn
    finally:
        conn.execute(f"DROP SCHEMA {schema} CASCADE")
        conn.close()


def iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def alert(rule="brute_force", at=T0, ip=ATTACKER, user="admin", severity="high", tactic="Credential Access",
          count=5, trigger="early", window_s=60):
    """An alert exactly as the stream processor emits it on security.alerts."""
    entity = f"src_ip={ip},user={user}" if user else f"src_ip={ip}"
    return {
        "alert_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{rule}|{entity}|{at.timestamp()}")),
        "rule_name": rule, "description": rule, "severity": severity, "technique": "T1110.001",
        "tactic": tactic, "entity": entity, "src_ip": ip, "user": user, "dest_ip": None,
        "window_start": iso(at), "window_end": iso(at + timedelta(seconds=window_s)),
        "count": count, "threshold": 5, "trigger": trigger,
        "event_time": iso(at + timedelta(seconds=4)), "first_event_time": iso(at),
        "sample_event_ids": [str(uuid.uuid4()) for _ in range(3)], "trigger_event_id": str(uuid.uuid4()),
        "detected_at": iso(at + timedelta(seconds=4, milliseconds=40)), "detection_latency_ms": 40.0,
        "processor": {"group": GROUP_ID, "window_s": window_s, "slide_s": 10},
    }


def put(conn, topic, value, offset=[0]) -> bool:
    """Store one message the way the writer's main loop does."""
    offset[0] += 1
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    with conn.transaction(), conn.cursor() as cur:
        return writer.store(conn, cur, topic, 0, offset[0], raw)


def one(conn, sql, *params):
    return conn.execute(sql, params).fetchone()


# ------------------------------------------------------------------ alerts

def test_alert_versions_upsert_into_one_row(db):
    a = alert()
    put(db, TOPIC_ALERTS, a)
    put(db, TOPIC_ALERTS, {**a, "count": 15, "severity": "critical", "trigger": "escalated",
                           "detected_at": iso(T0 + timedelta(seconds=9))})
    put(db, TOPIC_ALERTS, {**a, "count": 15, "severity": "critical", "trigger": "escalated",
                           "detected_at": iso(T0 + timedelta(seconds=9))})        # Kafka replay
    n, count, trigger, sev, first, latest = one(
        db, "SELECT count(*), max(count), max(trigger), max(severity), min(first_detected_at), "
            "max(detected_at) FROM alerts")
    assert (n, count, trigger, sev) == (1, 15, "escalated", "critical")
    assert first < latest                       # first detection time survives later versions


def test_alerts_from_other_processor_groups_are_ignored(db):
    put(db, TOPIC_ALERTS, {**alert(), "processor": {"group": "e2e-processor-1234"}})
    assert one(db, "SELECT count(*) FROM alerts")[0] == 0


# ------------------------------------------------------------------ incidents

def test_alerts_from_one_attacker_chain_into_a_multi_stage_incident(db):
    put(db, TOPIC_ALERTS, alert("port_scan", T0, user=None, severity="medium", tactic="Discovery"))
    put(db, TOPIC_ALERTS, alert("injection_probe", T0 + timedelta(minutes=2), user=None,
                                severity="medium", tactic="Initial Access"))
    put(db, TOPIC_ALERTS, alert("brute_force", T0 + timedelta(minutes=4)))
    n, entity, tactics, sev, alerts = one(db, "SELECT count(*) OVER (), entity, tactics, severity, alert_count "
                                              "FROM incidents")
    assert (n, entity, alerts) == (1, ATTACKER, 3)
    assert tactics == ["Discovery", "Initial Access", "Credential Access"]   # in order of appearance
    assert sev == "critical"                    # worst alert (high), raised one level for multi-stage


def test_a_quiet_gap_starts_a_new_incident(db):
    put(db, TOPIC_ALERTS, alert("brute_force", T0))
    put(db, TOPIC_ALERTS, alert("brute_force", T0 + timedelta(minutes=30)))
    assert one(db, "SELECT count(*) FROM incidents")[0] == 2


def test_single_tactic_incident_keeps_its_severity(db):
    put(db, TOPIC_ALERTS, alert("brute_force", T0, severity="high"))
    assert one(db, "SELECT severity, cardinality(tactics) FROM incidents") == ("high", 1)


# ------------------------------------------------------------------ other topics

def test_aggregates_and_metrics(db):
    agg = {"window_start": iso(T0), "window_end": iso(T0 + timedelta(minutes=1)), "source_type": "auth",
           "event_count": 40, "unique_ips": 3, "unique_users": 2, "success_count": 30, "fail_count": 9,
           "denied_count": 1, "processor": {"group": GROUP_ID}}
    put(db, TOPIC_AGGREGATES, agg)
    put(db, TOPIC_AGGREGATES, {**agg, "event_count": 41})                     # window re-sent
    put(db, TOPIC_METRICS, {"at": iso(T0), "group": GROUP_ID, "events_per_s": 12.5, "consumer_lag": 0,
                            "watermark_delay_s": 10.2, "detection_latency_ms": {"p50": 41, "p95": 90, "p99": 110}})
    assert one(db, "SELECT count(*), max(event_count) FROM aggregates") == (1, 41)
    assert one(db, "SELECT latency_p95_ms FROM pipeline_metrics")[0] == 90


# ------------------------------------------------------------------ bad messages

@pytest.mark.parametrize("bad", [
    b"{not json",
    json.dumps({"processor": {"group": GROUP_ID}}).encode(),                  # missing every field
    json.dumps({**alert(), "src_ip": "not-an-ip"}).encode(),                  # Postgres rejects inet
])
def test_bad_message_is_rejected_without_losing_the_batch(db, bad):
    good = alert()
    with db.transaction(), db.cursor() as cur:                                # one Kafka batch
        assert writer.store(db, cur, TOPIC_ALERTS, 0, 1, bad) is False
        assert writer.store(db, cur, TOPIC_ALERTS, 0, 2, json.dumps(good).encode()) is True
    assert one(db, "SELECT count(*) FROM alerts")[0] == 1
    assert one(db, 'SELECT topic, "offset" FROM warehouse_rejects') == (TOPIC_ALERTS, 1)
    with db.transaction(), db.cursor() as cur:                                # replay after restart
        writer.store(db, cur, TOPIC_ALERTS, 0, 1, bad)
    assert one(db, "SELECT count(*) FROM warehouse_rejects")[0] == 1


def test_schema_can_be_reapplied(db):
    writer.apply_schema(db)                     # what every writer start does


# ------------------------------------------------------------------ views

def test_analytical_views(db):
    put(db, TOPIC_ALERTS, alert("port_scan", T0, user=None, severity="medium", tactic="Discovery"))
    put(db, TOPIC_ALERTS, alert("brute_force_success", T0 + timedelta(minutes=1), severity="critical",
                                tactic="Initial Access"))
    put(db, TOPIC_ALERTS, alert("brute_force", T0, ip="127.66.0.9"))

    rows = db.execute("SELECT src_ip, alerts, rules, max_severity FROM hourly_ip_stats ORDER BY src_ip").fetchall()
    assert rows == [(ATTACKER, 2, ["brute_force_success", "port_scan"], "critical"),
                    ("127.66.0.9", 1, ["brute_force"], "high")]

    by_rule = dict(db.execute("SELECT rule_name, alerts FROM attack_type_breakdown").fetchall())
    assert by_rule == {"port_scan": 1, "brute_force_success": 1, "brute_force": 1}

    actor = one(db, "SELECT severity, incidents, multi_stage, compromised_account FROM threat_actors "
                    "WHERE entity = %s", ATTACKER)
    assert actor == ("critical", 1, True, True)
