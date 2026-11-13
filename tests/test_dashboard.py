"""Dashboard API tests: real PostgreSQL + a temporary Parquet lake. No Kafka needed.

The live Kafka bridge and the summariser loop are switched off; every SQL endpoint runs
against a throwaway Postgres schema filled through the real warehouse writer.
Skipped when no database is reachable (`docker compose up -d postgres`).

    python -m pytest tests/test_dashboard.py -v
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import psycopg
import pytest
from fastapi.testclient import TestClient

from dashboard import api
from lake import writer as lake_writer
from processor.config import TOPIC_ALERTS
from tests.test_lake import raw
from tests.test_warehouse import ATTACKER, alert, iso
from warehouse import writer

NOW = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=5)


@pytest.fixture
def client(tmp_path, monkeypatch):
    try:
        conn = psycopg.connect(writer.DSN, autocommit=True, connect_timeout=3)
    except psycopg.OperationalError as exc:
        pytest.skip(f"no PostgreSQL: {exc}")
    schema = f"test_{uuid.uuid4().hex[:8]}"
    conn.execute(f"CREATE SCHEMA {schema}")
    conn.execute(f"SET search_path TO {schema}")
    writer.apply_schema(conn)

    # The lake: ten raw events from the attacker, flushed to Parquet like the lake writer does.
    events = [raw(NOW + timedelta(seconds=s), ip=ATTACKER) for s in range(10)]
    lake_writer.flush([lake_writer.to_row(e, 0, i) for i, e in enumerate(events)], lake_dir=tmp_path)
    ids = [json.loads(e)["event_id"] for e in events]

    # The warehouse: a two-stage incident whose alerts point at some of those events.
    a1 = {**alert("port_scan", NOW, user=None, severity="medium", tactic="Discovery"),
          "sample_event_ids": ids[:3], "event_time": iso(NOW + timedelta(seconds=9))}
    a2 = {**alert("brute_force_success", NOW + timedelta(seconds=5), severity="critical", tactic="Initial Access"),
          "sample_event_ids": ids[5:7] + [str(uuid.uuid4())]}           # one id never reached the lake
    with conn.transaction(), conn.cursor() as cur:
        for i, a in enumerate((a1, a2)):
            writer.store(conn, cur, TOPIC_ALERTS, 0, i, json.dumps(a).encode())

    async def no_summaries():
        return None
    monkeypatch.setattr(api, "DSN", writer.DSN + ("&" if "?" in writer.DSN else "?") +
                        "options=" + quote(f"-csearch_path={schema}"))
    monkeypatch.setattr(api, "kafka_bridge", lambda loop, stop: None)
    monkeypatch.setattr(api.summariser, "run", no_summaries)
    monkeypatch.setattr(api, "LAKE_DIR", tmp_path)
    try:
        with TestClient(api.app) as c:
            c.alerts = (a1, a2)
            c.event_ids = ids
            yield c
    finally:
        conn.execute(f"DROP SCHEMA {schema} CASCADE")
        conn.close()


def test_health(client):
    h = client.get("/api/health").json()
    assert h["warehouse"] == "up" and h["lake_exists"]


def test_summary_counts_warehouse_and_lake(client):
    s = client.get("/api/summary").json()
    assert s["warehouse"]["alerts"] == 2 and s["incidents"] == {"total": 1, "multi_stage": 1}
    assert s["lake"]["files"] == 1 and s["lake"]["rows"] == 10


def test_alerts_and_incident_detail(client):
    alerts = client.get("/api/alerts").json()
    assert {a["rule_name"] for a in alerts} == {"port_scan", "brute_force_success"}
    inc = client.get(f"/api/incidents/{alerts[0]['incident_id']}").json()
    assert inc["multi_stage"] and [a["rule_name"] for a in inc["alerts"]] == ["port_scan", "brute_force_success"]
    assert client.get(f"/api/incidents/{uuid.uuid4()}").status_code == 404


def test_alert_events_reads_raw_events_back_from_the_lake(client):
    a1, a2 = client.alerts
    got = client.get(f"/api/alerts/{a1['alert_id']}/events").json()
    assert sorted(e["event_id"] for e in got["events"]) == sorted(client.event_ids[:3])
    assert got["missing"] == []
    got = client.get(f"/api/alerts/{a2['alert_id']}/events").json()
    assert len(got["events"]) == 2 and got["missing"] == [a2["sample_event_ids"][-1]]
    assert client.get(f"/api/alerts/{uuid.uuid4()}/events").status_code == 404


def test_view_endpoints(client):
    actors = client.get("/api/threat-actors").json()
    assert [(a["entity"], a["severity"], a["compromised_account"]) for a in actors] == [(ATTACKER, "critical", True)]
    assert {r["rule_name"] for r in client.get("/api/attack-types").json()} == {"port_scan", "brute_force_success"}
    assert client.get("/api/ip-stats").json()[0]["src_ip"] == ATTACKER


def test_limits_are_validated(client):
    assert client.get("/api/alerts?limit=0").status_code == 422
    assert client.get("/api/alerts?limit=100000").status_code == 422
