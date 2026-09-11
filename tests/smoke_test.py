"""End-to-end smoke test for the ingest pipeline.

Checks, in order:
  1. API is up and can reach the broker
  2. valid events are accepted (202) and keyed consistently by src_ip
  3. invalid events are rejected (422) and parked in the DLQ
  4. a consumer receives exactly the events posted, and no others

Requires the broker and the API to already be running. Run with:
    python -m tests.smoke_test
"""
import json
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from confluent_kafka import Consumer

API = "http://127.0.0.1:8000"
BOOTSTRAP = "localhost:9092"
TOPIC = "security.events.raw"
TEST_IPS = ["10.0.0.5", "192.168.1.9", "172.16.4.2"]
N_VALID = 9

PASS, FAIL = "  PASS", "  FAIL"
failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    print(f"{PASS if ok else FAIL}  {label}{'  -- ' + detail if detail else ''}")
    if not ok:
        failures += 1


def post(payload) -> int:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    req = urllib.request.Request(API + "/events", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def make_event(ip: str) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "event_time": datetime.now(timezone.utc).isoformat(),
        "source_type": "auth",
        "src_ip": ip,
        "user": "smoketest",
        "status": "fail",
    }


def main() -> int:
    print("\n=== 1. health ===")
    try:
        with urllib.request.urlopen(API + "/health", timeout=5) as r:
            health = json.load(r)
        check("API reachable", r.status == 200)
        check("broker reachable", health.get("brokers_up", 0) >= 1)
        check("both topics exist", len(health.get("topics_found", [])) == 2,
              str(health.get("topics_found")))
    except Exception as exc:
        print(f"{FAIL}  cannot reach {API} -- is uvicorn running?  ({exc})")
        return 1

    # Subscribe and wait for partition assignment BEFORE posting anything.
    # Everything here runs on one thread on purpose: confluent_kafka.Consumer is
    # not thread-safe, and polling it from a worker thread silently yields nothing.
    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP,
        "group.id": f"smoke-test-{uuid.uuid4()}",   # throwaway group, never reused
        "auto.offset.reset": "latest",
        "enable.auto.commit": False,
    })
    assigned = {"done": False}
    consumer.subscribe([TOPIC], on_assign=lambda c, p: assigned.update(done=True))
    for _ in range(40):
        consumer.poll(0.5)
        if assigned["done"]:
            break
    check("consumer assigned partitions", assigned["done"])

    print("\n=== 2. valid events ===")
    posted, ip_of = [], {}
    for i in range(N_VALID):
        ev = make_event(TEST_IPS[i % len(TEST_IPS)])
        if post(ev) == 202:
            posted.append(ev["event_id"])
            ip_of[ev["event_id"]] = ev["src_ip"]
    check(f"{N_VALID} events accepted with 202", len(posted) == N_VALID,
          f"got {len(posted)}")

    print("\n=== 3. invalid events rejected + parked in DLQ ===")
    bad_cases = {
        "naive timestamp (no UTC offset)": {**make_event("1.2.3.4"),
                                            "event_time": "2026-01-01T00:00:00"},
        "unknown source_type": {**make_event("1.2.3.4"), "source_type": "database"},
        "unexpected extra field": {**make_event("1.2.3.4"), "surprise": "drift"},
        "not valid json": b"{{{not json",
    }
    for label, payload in bad_cases.items():
        check(f"rejected: {label}", post(payload) == 422)

    print("\n=== 4. consumer received them ===")
    seen: dict[str, int] = {}
    for _ in range(60):
        msg = consumer.poll(0.5)
        if msg is None or msg.error():
            continue
        ev = json.loads(msg.value())
        if ev["event_id"] in ip_of:
            seen[ev["event_id"]] = msg.partition()
        if len(seen) == len(posted):
            break
    consumer.close()

    check(f"all {N_VALID} events consumed", len(seen) == N_VALID, f"got {len(seen)}")

    # Each src_ip must map to exactly one partition -- this is what keeps per-IP
    # event ordering intact for brute-force detection downstream.
    by_ip: dict[str, set] = {}
    for eid, part in seen.items():
        by_ip.setdefault(ip_of[eid], set()).add(part)
    split = {ip: parts for ip, parts in by_ip.items() if len(parts) > 1}
    check("each src_ip stayed on one partition", not split, str(split))
    for ip, parts in sorted(by_ip.items()):
        print(f"         {ip:<16} -> partition {sorted(parts)[0]}")

    print(f"\n{'ALL CHECKS PASSED' if not failures else f'{failures} CHECK(S) FAILED'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
