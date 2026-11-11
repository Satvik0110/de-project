"""Unit tests for the stream processor's parsing, windowing and rules. No Kafka needed.

    python -m pytest tests/test_processor.py -v
"""
import json
import uuid
from datetime import datetime, timezone

import pytest

from processor.engine import WindowEngine
from processor.model import Event, InvalidEvent, parse_event, split_dest
from processor.rules import default_rules

T0 = 1_800_000_000.0   # aligned to 10s and 60s


def ev(ts, source="auth", status="fail", ip="203.0.113.7", user="admin",
       dest=None, port=None, eid=None):
    return Event(event_id=eid or str(uuid.uuid4()), ts=ts, ingest_ts=ts,
                 source_type=source, src_ip=ip, status=status,
                 dest_ip=dest, dest_port=port, user=user)


def engine(**kw):
    kw.setdefault("window_s", 60)
    kw.setdefault("slide_s", 10)
    kw.setdefault("lateness_s", 10)
    return WindowEngine(default_rules(), **kw)


def feed(e, events, now=None):
    alerts = []
    for x in events:
        alerts += e.add(x, now or x.ts)
    return alerts


def rules_fired(alerts):
    return sorted({a["rule_name"] for a in alerts})


# ----------------------------------------------------------------- parsing

def raw(**over):
    d = {"event_id": str(uuid.uuid4()), "event_time": "2026-10-18T10:00:00Z",
         "ingest_time": "2026-10-18T10:00:00.050Z", "source_type": "network",
         "src_ip": " 10.0.0.5", "status": "denied", "dest_ip_port": "10.0.0.1:443",
         "user": "  Admin "}
    d.update(over)
    return json.dumps(d).encode()


NOW = datetime(2026, 10, 18, 10, 0, 5, tzinfo=timezone.utc).timestamp()


def test_parse_normalises_fields():
    e = parse_event(raw(), NOW, 60)
    assert e.src_ip == "10.0.0.5"
    assert (e.dest_ip, e.dest_port) == ("10.0.0.1", 443)
    assert e.user == "admin"
    assert e.ingest_ts - e.ts == pytest.approx(0.05)


@pytest.mark.parametrize("dest,expected", [
    ("10.0.0.1:22", ("10.0.0.1", 22)),
    ("10.0.0.1", ("10.0.0.1", None)),
    ("[2001:db8::1]:8443", ("2001:db8::1", 8443)),
    ("2001:DB8::1", ("2001:db8::1", None)),
    (None, (None, None)),
])
def test_split_dest(dest, expected):
    assert split_dest(dest) == expected


@pytest.mark.parametrize("over,reason", [
    ({"src_ip": "not-an-ip"}, "src_ip"),
    ({"dest_ip_port": "10.0.0.1:99999"}, "port"),
    ({"event_time": "2026-10-18T10:00:00"}, "schema"),           # naive timestamp
    ({"event_time": "2026-10-18T11:00:00Z"}, "future"),          # 1h ahead of NOW
    ({"source_type": "database"}, "schema"),
])
def test_parse_rejects(over, reason):
    with pytest.raises(InvalidEvent, match=reason):
        parse_event(raw(**over), NOW, 60)


def test_parse_rejects_garbage():
    with pytest.raises(InvalidEvent):
        parse_event(b"{{{", NOW, 60)


# ------------------------------------------------------------------- rules

def test_brute_force_fires_early_at_threshold():
    e = engine()
    alerts = feed(e, [ev(T0 + i) for i in range(4)])
    assert alerts == []
    alerts = feed(e, [ev(T0 + 4)])
    assert rules_fired(alerts) == ["brute_force"]
    a = alerts[0]
    assert a["count"] == 5 and a["trigger"] == "early" and a["severity"] == "high"
    assert a["src_ip"] == "203.0.113.7" and a["user"] == "admin"
    assert len(a["sample_event_ids"]) == 5


def test_below_threshold_is_silent():
    e = engine()
    alerts = feed(e, [ev(T0 + i, user=f"u{i % 2}") for i in range(8)])   # 4 fails per user
    assert "brute_force" not in rules_fired(alerts)


def test_failures_outside_one_window_do_not_add_up():
    e = engine()
    # 3 fails, then 3 more 90s later: never 5 in any 60s window
    alerts = feed(e, [ev(T0 + i) for i in range(3)] + [ev(T0 + 90 + i) for i in range(3)])
    assert alerts == []


def test_password_spray_vs_brute_force():
    e = engine()
    alerts = feed(e, [ev(T0 + i, user=f"user{i}") for i in range(6)])
    assert rules_fired(alerts) == ["password_spray"]


def test_brute_force_success_needs_success_after_failures():
    e = engine()
    alerts = feed(e, [ev(T0, status="success")] + [ev(T0 + 1 + i) for i in range(5)])
    assert "brute_force_success" not in rules_fired(alerts)   # success came first
    alerts = feed(e, [ev(T0 + 7, status="success")])
    assert rules_fired(alerts) == ["brute_force_success"]
    assert alerts[0]["severity"] == "critical"


def test_distributed_brute_force():
    e = engine()
    alerts = feed(e, [ev(T0 + i, ip=f"198.51.100.{i}", user="ceo") for i in range(6)])
    assert rules_fired(alerts) == ["distributed_brute_force"]
    assert alerts[0]["user"] == "ceo" and alerts[0]["src_ip"] is None


def test_port_scan_and_host_sweep_are_distinct():
    e = engine()
    scan = [ev(T0 + i * 0.1, source="network", status="denied", user=None,
               dest="10.0.0.1", port=1000 + i) for i in range(12)]
    assert rules_fired(feed(e, scan)) == ["port_scan"]
    sweep = [ev(T0 + i * 0.1, source="network", status="denied", user=None, ip="198.51.100.9",
                dest=f"10.0.1.{i}", port=22) for i in range(12)]
    assert rules_fired(feed(e, sweep)) == ["host_sweep"]


def test_api_flood_and_probing():
    e = engine()
    flood = [ev(T0 + i * 0.05, source="api", status="success", user=None) for i in range(55)]
    assert rules_fired(feed(e, flood)) == ["api_flood"]
    probe = [ev(T0 + i * 0.1, source="api", status="denied", user=None, ip="198.51.100.3")
             for i in range(12)]
    assert rules_fired(feed(e, probe)) == ["api_access_probing"]


def test_severity_escalates_at_3x_threshold():
    e = engine()
    alerts = feed(e, [ev(T0 + i * 0.1) for i in range(15)])
    assert [(a["trigger"], a["severity"]) for a in alerts] == [("early", "high"), ("escalated", "critical")]
    assert alerts[0]["alert_id"] == alerts[1]["alert_id"]


# ---------------------------------------------------- windows / watermark

def test_one_alert_per_attack_and_final_count_on_close():
    e = engine()
    alerts = feed(e, [ev(T0 + i) for i in range(12)])   # 12 fails within 12s
    assert len(alerts) == 1                              # overlapping windows suppressed
    e.advance_wallclock(T0 + 200)
    final, _ = e.close_ready(T0 + 200)
    assert len(final) == 1
    assert final[0]["trigger"] == "final" and final[0]["count"] == 12
    assert final[0]["alert_id"] == alerts[0]["alert_id"]


def test_sustained_attack_alerts_again_in_non_overlapping_window():
    e = engine()
    alerts = []
    for i in range(0, 150, 2):                           # one fail every 2s for 150s
        alerts += e.add(ev(T0 + i), T0 + i)
        alerts += e.close_ready(T0 + i)[0]
    early = [a for a in alerts if a["trigger"] == "early"]
    assert len(early) >= 2
    starts = sorted(a["window_start"] for a in early)
    assert len(set(starts)) == len(starts)


def test_duplicates_are_dropped():
    e = engine()
    x = ev(T0)
    assert e.add(x, T0) == [] and e.add(x, T0) == []
    assert e.stats["duplicate"] == 1 and e.stats["accepted"] == 1
    alerts = feed(e, [ev(T0 + 1, eid=f"dup-{i % 2}") for i in range(10)])
    assert alerts == []                                  # only 3 distinct events


def test_out_of_order_within_lateness_is_counted():
    e = engine()
    feed(e, [ev(T0 + 30), ev(T0 + 31), ev(T0 + 32), ev(T0 + 33)])
    alerts = feed(e, [ev(T0 + 25)])                      # 8s older than newest event
    assert rules_fired(alerts) == ["brute_force"]


def test_events_for_emitted_windows_are_late():
    e = engine()
    e.add(ev(T0), T0)
    e.add(ev(T0 + 200, ip="10.9.9.9"), T0 + 200)         # watermark -> T0+190
    e.close_ready(T0 + 200)
    assert e.add(ev(T0 + 5), T0 + 200) == []
    assert e.stats["late"] == 1


def test_idle_wallclock_closes_windows():
    e = engine()
    e.add(ev(T0), T0)
    assert e.close_ready(T0 + 1) == ([], [])
    e.advance_wallclock(T0 + 75)                         # watermark = T0+65
    _, aggs = e.close_ready(T0 + 75)
    assert [(a["source_type"], a["event_count"]) for a in aggs] == [("auth", 1)]


def test_aggregates_are_tumbling():
    e = engine()
    feed(e, [ev(T0 + i, ip=f"10.0.0.{i % 3}", status="success" if i % 2 else "fail",
                user=f"u{i}") for i in range(4)])
    feed(e, [ev(T0 + 5, source="api", status="success", user=None)])
    e.advance_wallclock(T0 + 1000)
    _, aggs = e.close_ready(T0 + 1000)
    by_src = {a["source_type"]: a for a in aggs}
    assert len(aggs) == 2                                # one window, not six overlapping
    assert by_src["auth"]["event_count"] == 4
    assert by_src["auth"]["unique_ips"] == 3
    assert (by_src["auth"]["success_count"], by_src["auth"]["fail_count"]) == (2, 2)
    assert by_src["auth"]["window_start"].startswith("2027-01-15T08:00:00")


def test_memory_is_released_after_windows_close():
    e = engine()
    feed(e, [ev(T0 + i) for i in range(20)])
    e.advance_wallclock(T0 + 1000)
    e.close_ready(T0 + 1000)
    assert e.state_size() == {"open_panes": 0, "dedup_ids": 0, "open_alerts": 0}
    assert not e.last_alert


# ---------------------------------------------------------- offsets / restart

def test_offsets_commit_only_past_closed_windows():
    e = engine()
    e.add(ev(T0), T0, partition=0, offset=10)
    e.add(ev(T0 + 1), T0, partition=0, offset=11)
    e.add(ev(T0 + 1, ip="10.1.1.1"), T0, partition=1, offset=4)
    e.note_offset(2, 7)                                  # e.g. an invalid record
    assert e.committable_offsets() == {0: 10, 1: 4, 2: 8}
    e.advance_wallclock(T0 + 1000)
    e.close_ready(T0 + 1000)
    assert e.committable_offsets() == {0: 12, 1: 5, 2: 8}


def test_restart_replay_reproduces_same_alert():
    events = [ev(T0 + i) for i in range(8)]
    first = engine()
    a1 = feed(first, events)
    checkpoint = json.loads(first.checkpoint())

    second = engine()                                    # fresh process, same events replayed
    second.restore(checkpoint["closed_before"])
    a2 = feed(second, events)
    assert [a["alert_id"] for a in a1] == [a["alert_id"] for a in a2]


def test_restore_drops_events_of_already_emitted_windows():
    first = engine()
    first.add(ev(T0), T0)
    first.advance_wallclock(T0 + 1000)
    first.close_ready(T0 + 1000)
    cp = json.loads(first.checkpoint())

    second = engine()
    second.restore(cp["closed_before"])
    assert second.add(ev(T0 + 1), T0 + 1000) == []
    assert second.stats["late"] == 1
