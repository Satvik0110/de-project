"""End-to-end test: ingest API -> Kafka -> stream processor -> security.alerts.

Starts its own processor (throwaway consumer group, short 10s/2s windows so the test
finishes quickly), posts normal traffic plus every attack scenario through the real
API, and checks:
  1. each attack raises exactly the rules it should, and normal traffic raises none
  2. duplicates (same event_id re-sent) are not double counted
  3. a late event is dropped, and a record the processor rejects reaches the DLQ
  4. windows close, aggregates are emitted, metrics are published
  5. after a restart on the same group, nothing already emitted is re-emitted

Requires the broker and the ingest API to be running:
    python -m tests.e2e_processor
"""
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from confluent_kafka import Consumer

from processor import config
from tools import mock_traffic as mt

API = "http://127.0.0.1:8000"
GROUP = f"e2e-processor-{uuid.uuid4().hex[:8]}"
WINDOW, SLIDE, LATENESS, IDLE = 10, 2, 2, 2

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    print(f"{'  PASS' if ok else '  FAIL'}  {label}{'  -- ' + detail if detail else ''}")
    failures += not ok


def post(ev: dict) -> int:
    req = urllib.request.Request(API + "/events", data=json.dumps(ev).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def start_processor(log_path: str) -> subprocess.Popen:
    already = open(log_path).read().count("assigned partitions") if os.path.exists(log_path) else 0
    log = open(log_path, "a")
    env = {**os.environ, "METRICS_INTERVAL_S": "2", "COMMIT_INTERVAL_S": "1"}
    p = subprocess.Popen(
        [sys.executable, "-m", "processor.main", "--group", GROUP, "--latest",
         "--window", str(WINDOW), "--slide", str(SLIDE), "--lateness", str(LATENESS),
         "--idle-advance", str(IDLE)],
        stdout=log, stderr=subprocess.STDOUT, env=env)
    deadline = time.time() + 30
    while time.time() < deadline:
        if open(log_path).read().count("assigned partitions") > already:
            return p
        time.sleep(0.3)
    p.kill()
    raise SystemExit(f"processor did not get partitions in 30s, see {log_path}")


def stop_processor(p: subprocess.Popen) -> int:
    p.send_signal(signal.SIGINT)
    return p.wait(timeout=30)


def output_consumer() -> Consumer:
    c = Consumer({"bootstrap.servers": config.KAFKA_BOOTSTRAP, "group.id": f"{GROUP}-reader",
                  "auto.offset.reset": "latest", "enable.auto.commit": False})
    assigned = {"n": 0}
    c.subscribe([config.TOPIC_ALERTS, config.TOPIC_AGGREGATES, config.TOPIC_METRICS, config.TOPIC_DLQ],
                on_assign=lambda _c, parts: assigned.update(n=len(parts)))
    for _ in range(60):
        c.poll(0.5)
        if assigned["n"]:
            break
    return c


def drain(c: Consumer, seconds: float, out: dict) -> None:
    end = time.time() + seconds
    while time.time() < end:
        msg = c.poll(0.3)
        if msg is None or msg.error():
            continue
        v = json.loads(msg.value())
        if msg.topic() == config.TOPIC_DLQ:
            out["dlq"].append(v)
        elif (v.get("processor") or {}).get("group", v.get("group")) == GROUP:
            out[msg.topic()].append(v)


def main() -> int:
    log_path = f"/tmp/{GROUP}.log"
    print(f"processor group {GROUP}, log {log_path}")
    try:
        with urllib.request.urlopen(API + "/health", timeout=5) as r:
            check("ingest API + broker healthy", json.load(r).get("status") == "ok")
    except Exception as exc:
        print(f"  FAIL  cannot reach {API} ({exc}) -- is uvicorn running?")
        return 1

    reader = output_consumer()
    proc = start_processor(log_path)
    out = {config.TOPIC_ALERTS: [], config.TOPIC_AGGREGATES: [], config.TOPIC_METRICS: [], "dlq": []}

    print("\n=== 1. traffic ===")
    for _ in range(100):
        post(mt.normal_event(mt.random.Random()))
    expected = {}
    bf_ids = []
    for name, scenario in mt.ATTACKS.items():
        evs, exp = scenario()
        expected.update(exp)
        for ev in evs:
            post(ev)
            if name == "brute_force":
                post(ev)                    # every brute-force event sent twice
                bf_ids.append(ev["event_id"])
    print(f"  posted 100 normal events + {len(mt.ATTACKS)} attack scenarios")

    bad_id = str(uuid.uuid4())   # passes the API's schema, fails the processor's IP check
    check("API accepts record with non-IP src_ip", post(
        {**mt.event("not-an-ip", "auth", "fail", "x"), "event_id": bad_id}) == 202)

    # Let the windows close: window + lateness + idle advance + slack
    drain(reader, WINDOW + LATENESS + IDLE + 6, out)

    late = mt.event("203.0.113.99", "auth", "fail", "late",
                    at=datetime.now(timezone.utc) - timedelta(seconds=120))
    post(late)
    drain(reader, 6, out)

    print("\n=== 2. alerts ===")
    alerts = out[config.TOPIC_ALERTS]
    fired: dict = {}
    for a in alerts:
        entity = f"user:{a['user']}" if a["rule_name"] == "distributed_brute_force" else a["src_ip"]
        fired.setdefault(entity, set()).add(a["rule_name"])
    for entity, rules in expected.items():
        check(f"{entity:<22} -> {', '.join(sorted(rules))}", fired.get(entity) == rules,
              f"got {sorted(fired.get(entity, []))}")
    normal_hits = {e: r for e, r in fired.items() if e and e.startswith("10.0.")}
    check("normal traffic raised no alerts", not normal_hits, str(normal_hits))
    extra = set(fired) - set(expected)
    check("no unexpected alert entities", not extra, str(extra))

    early = [a for a in alerts if a["trigger"] == "early"]
    lat = sorted(a["detection_latency_ms"] for a in early)
    if lat:
        print(f"         detection latency (early alerts): median {lat[len(lat) // 2]:.0f} ms, "
              f"max {lat[-1]:.0f} ms over {len(lat)} alerts")
    check("alerts fire early (before window close)", bool(early) and lat[-1] < 2000)

    print("\n=== 3. dedup, late data, DLQ ===")
    bf = [a for a in alerts if a["rule_name"] == "brute_force" and a["src_ip"] == "203.0.113.10"]
    bf_final = max((a["count"] for a in bf), default=0)
    check("brute_force counted 12 events, not 24 (duplicates dropped)", bf_final == 12, f"got {bf_final}")
    check("alert carries provenance (sample event ids)",
          bool(bf) and set(bf[-1]["sample_event_ids"]) <= set(bf_ids))
    metrics = out[config.TOPIC_METRICS]
    totals = metrics[-1]["totals"] if metrics else {}
    check("processor counted duplicates", totals.get("duplicate", 0) >= 12, str(totals))
    check("late event dropped", totals.get("late", 0) >= 1, str(totals))
    check("non-IP src_ip rejected to DLQ by processor",
          any(d.get("stage") == "stream-processor" and bad_id in d.get("raw_body", "") for d in out["dlq"]))

    print("\n=== 4. windows, aggregates, metrics ===")
    aggs = out[config.TOPIC_AGGREGATES]
    check("aggregates emitted", bool(aggs), f"{len(aggs)} rows")
    check("aggregates cover all source types", {a["source_type"] for a in aggs} == {"auth", "network", "api"})
    check("metrics published", bool(metrics))
    check("windows closed", totals.get("windows_closed", 0) > 0)
    check("alerts got a final update on close", any(a["trigger"] == "final" for a in alerts))

    print("\n=== 5. restart ===")
    check("processor exits cleanly on SIGINT", stop_processor(proc) == 0)
    n_before = len(out[config.TOPIC_ALERTS])
    proc = start_processor(log_path)
    restored = "already emitted" in open(log_path).read().split("assigned partitions")[-1]
    check("restart resumed from checkpoint", restored)
    drain(reader, IDLE + 4, out)
    check("no alerts re-emitted after restart", len(out[config.TOPIC_ALERTS]) == n_before,
          f"{len(out[config.TOPIC_ALERTS]) - n_before} new")
    stop_processor(proc)
    reader.close()

    print(f"\n{'ALL CHECKS PASSED' if not failures else f'{failures} CHECK(S) FAILED'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
