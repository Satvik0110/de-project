"""End-to-end test of the whole platform, driven exactly as in the demo.

Launches every scenario through the simulator API (real HTTP/TCP against the target and
sensor, events logged by the defended side), then checks:
  1. each campaign raised all of its expected rules, from its attacker IP(s)
  2. benign employee traffic (127.0.1.x) raised no alert
  3. alerts carry ATT&CK tags and fire early (sub-second detection latency)
  4. the lake has Parquet files; if Postgres is up: incidents (incl. a multi-stage one)
     and the scoreboard agree

Requires the services from scripts/start.sh (UIs not needed):
    python -m tests.e2e_platform
"""
import json
import sys
import time
import urllib.request
import uuid

from confluent_kafka import Consumer

from processor.config import GROUP_ID, KAFKA_BOOTSTRAP, TOPIC_ALERTS

SIM, DASH = "http://127.0.0.1:8001", "http://127.0.0.1:8003"
failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    print(f"{'  PASS' if ok else '  FAIL'}  {label}{'  -- ' + detail if detail else ''}")
    failures += not ok


def call(url: str, body: dict | None = None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def main() -> int:
    c = Consumer({"bootstrap.servers": KAFKA_BOOTSTRAP, "group.id": f"e2e-platform-{uuid.uuid4().hex[:6]}",
                  "auto.offset.reset": "latest", "enable.auto.commit": False})
    assigned = []
    c.subscribe([TOPIC_ALERTS], on_assign=lambda _c, p: assigned.extend(p))
    while not assigned:
        c.poll(0.5)

    state = call(SIM + "/api/state")
    call(SIM + "/api/background", {"enabled": True})
    print("=== launching", len(state["scenarios"]), "scenarios ===")
    launched = {}
    for sc in state["scenarios"]:
        launched[call(SIM + "/api/attack", {"scenario": sc["id"]})["campaign_id"]] = sc
        time.sleep(0.5)

    alerts, deadline = [], time.time() + 75
    while time.time() < deadline:
        msg = c.poll(0.5)
        if msg and not msg.error():
            a = json.loads(msg.value())
            if a["processor"]["group"] == GROUP_ID:
                alerts.append(a)
        done = [x for x in call(SIM + "/api/state")["campaigns"] if x["campaign_id"] in launched]
        if done and all(x["status"] == "done" for x in done) and time.time() > deadline - 55:
            break
    c.close()
    campaigns = {x["campaign_id"]: x for x in call(SIM + "/api/state")["campaigns"] if x["campaign_id"] in launched}

    print("\n=== 1. every attack detected by its expected rules ===")
    for cid, camp in campaigns.items():
        ips = set(camp["attacker_ips"])
        fired = {a["rule_name"] for a in alerts
                 if a["src_ip"] in ips or (a["src_ip"] is None and a["user"] == camp.get("target_user"))}
        exp = set(camp["expected_rules"])
        check(f"{camp['scenario']:<24} -> {', '.join(sorted(exp))}", exp <= fired,
              f"fired {sorted(fired)}")

    print("\n=== 2. no false positives on employee traffic ===")
    benign = [a for a in alerts if (a["src_ip"] or "").startswith("127.0.1.")]
    check("no alerts on 127.0.1.x", not benign, str([(a["rule_name"], a["entity"]) for a in benign]))

    print("\n=== 3. alert quality ===")
    check("all alerts have ATT&CK technique + tactic", all(a.get("technique") and a.get("tactic") for a in alerts))
    lat = sorted(a["detection_latency_ms"] for a in alerts if a["trigger"] == "early" and a["detection_latency_ms"])
    if lat:
        print(f"         detection latency: p50 {lat[len(lat) // 2]:.0f} ms, max {lat[-1]:.0f} ms ({len(lat)} alerts)")
    check("early alerts detected in under 1 s (p50)", bool(lat) and lat[len(lat) // 2] < 1000)

    print("\n=== 4. storage + scoreboard ===")
    try:
        s = call(DASH + "/api/summary")
    except Exception as exc:
        print(f"  SKIP  dashboard API not reachable ({exc})")
    else:
        check("lake has parquet files", s["lake"]["files"] > 0, str(s["lake"]))
        time.sleep(15)   # let the warehouse writer and summariser catch up
        incs = call(DASH + "/api/incidents")
        check("a multi-stage incident exists", any(i["multi_stage"] for i in incs))
        check("incidents get summaries", any(i["summary"] for i in incs))
        sb = call(DASH + "/api/scoreboard")
        ours = [x for x in sb["campaigns"] if x["campaign_id"] in launched]
        check("scoreboard: all launched campaigns detected", ours and all(x["detected"] for x in ours),
              str([(x["scenario"], x["missed_rules"]) for x in ours if x["missed_rules"]]))
        print(f"         recall {sb['recall']}, precision {sb['precision']}, median TTD {sb['median_ttd_ms']} ms")

    print(f"\n{'ALL CHECKS PASSED' if not failures else f'{failures} CHECK(S) FAILED'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
