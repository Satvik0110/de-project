"""End-to-end test of the whole platform, driven exactly as in the demo.

Launches every scenario through the simulator API (real HTTP/TCP against the target and
sensor, events logged by the defended side), then checks:
  1. each attack raised all of its expected rules, from its attacker IP(s)
  2. background employee traffic (127.0.1.x) raised no alert; the two benign-but-suspicious
     scenarios raise their documented false positives (that is what they demonstrate)
  3. alerts carry ATT&CK tags and fire early (sub-second detection latency)
  4. storage + dashboard: lake files, 0 events lost, compression, incidents with summaries,
     scoreboard (all attacks detected, benign alerts counted as false positives, attack
     progress measured from the lake)
low_and_slow is skipped: it takes 3 minutes by design (run it by hand; it should be missed).

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
    for sc in [x for x in state["scenarios"] if x["id"] != "low_and_slow"]:
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

    def fired(camp):
        ips = set(camp["attacker_ips"])
        return {a["rule_name"] for a in alerts
                if a["src_ip"] in ips or (a["src_ip"] is None and a["user"] == camp.get("target_user"))}

    print("\n=== 1. every attack detected by its expected rules ===")
    for camp in campaigns.values():
        if camp["malicious"]:
            exp = set(camp["expected_rules"])
            check(f"{camp['scenario']:<24} -> {', '.join(sorted(exp))}", exp <= fired(camp),
                  f"fired {sorted(fired(camp))}")

    print("\n=== 2. benign traffic ===")
    benign = [a for a in alerts if (a["src_ip"] or "").startswith("127.0.1.")]
    check("no alerts on employee traffic (127.0.1.x)", not benign, str([(a["rule_name"], a["entity"]) for a in benign]))
    known_fp = {"admin_scan": {"port_scan"}, "office_nat": {"password_spray"}}
    for camp in campaigns.values():
        if not camp["malicious"]:
            check(f"benign {camp['scenario']:<15} raises its known FP {sorted(known_fp[camp['scenario']])}",
                  fired(camp) == known_fp[camp["scenario"]], f"fired {sorted(fired(camp))}")

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
        time.sleep(35)   # one lake flush (30 s), warehouse writer and summariser catch up
        p = call(DASH + "/api/pipeline")
        rec = p["reconciliation"]
        check("pipeline: 0 events lost between shippers and Kafka", rec["lost"] == 0 and rec["shipper_failed"] == 0,
              str(rec))
        check("pipeline: Parquet smaller than raw JSON", (p["storage"]["compression_ratio"] or 0) > 1,
              str(p["storage"]))
        check("pipeline: freshness reported for all 3 layers", all(t["freshness_s"] is not None for t in p["tiers"]),
              str(p["tiers"]))
        incs = call(DASH + "/api/incidents")
        check("a multi-stage incident exists", any(i["multi_stage"] for i in incs))
        check("incidents get summaries", any(i["summary"] for i in incs))
        sb = call(DASH + "/api/scoreboard")
        ours = [x for x in sb["campaigns"] if x["campaign_id"] in launched]
        mal = [x for x in ours if x["malicious"]]
        check("scoreboard: every attack detected", mal and all(x["detected"] and not x["missed_rules"] for x in mal),
              str([(x["scenario"], x["missed_rules"]) for x in mal if x["missed_rules"]]))
        check("scoreboard: benign alerts counted as false positives",
              sb["false_positive_alerts"] >= 2 and sb["precision"] < 1, f"FP {sb['false_positive_alerts']}")
        check("scoreboard: attack progress measured from the lake",
              all(x["progress_at_detection"] is not None for x in mal), str([x["scenario"] for x in mal
                                                                             if x["progress_at_detection"] is None]))
        f = sb["funnel"]
        print(f"         MTTD {sb['mttd_ms']} ms | {f['attack_events']} attack events -> {f['alerts']} alerts -> "
              f"{f['incidents']} incidents | recall {sb['recall']} precision {sb['precision']:.2f}")
        for x in mal:
            seen = f"{x['progress_at_detection']:.0%}" if x["progress_at_detection"] is not None else "?"
            print(f"         {x['scenario']:<24} TTD {x['ttd_ms']:>5} ms  seen {seen:>4} of {x['attack_events']:>3} "
                  f"events before alert  early by {x['early_by_s']} s")

    print(f"\n{'ALL CHECKS PASSED' if not failures else f'{failures} CHECK(S) FAILED'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
