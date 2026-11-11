"""Mock traffic for exercising the pipeline until the real Attack Simulator (FR1) lands.

Posts events to the ingest API: a background of normal activity that should raise
no alerts, plus attack bursts each shaped to trigger exactly one family of rules.

    python -m tools.mock_traffic --scenario all
    python -m tools.mock_traffic --scenario brute_force --dup-rate 0.3
    python -m tools.mock_traffic --scenario normal --duration 60 --rate 20
    python -m tools.mock_traffic --list

Address ranges are chosen so results are easy to read: normal users come from
10.0.0.0/16, attackers from the documentation ranges 203.0.113.0/24 and 198.51.100.0/24.
"""
import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

SERVERS = [f"10.0.100.{i}" for i in range(1, 6)]
COMMON_PORTS = [22, 53, 80, 443]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
         "mallory", "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter"]


def event(src_ip, source_type, status, user=None, dest=None, at=None):
    return {
        "event_id": str(uuid.uuid4()),
        "event_time": (at or datetime.now(timezone.utc)).isoformat(),
        "source_type": source_type,
        "src_ip": src_ip,
        "status": status,
        "user": user,
        "dest_ip_port": dest,
    }


# --- scenarios: each returns (description, [events], {ip: expected rules}) -----

def brute_force(n=12, ip="203.0.113.10", user="admin"):
    return [event(ip, "auth", "fail", user, f"{SERVERS[0]}:22") for _ in range(n)], \
        {ip: {"brute_force"}}


def password_spray(n=8, ip="203.0.113.20"):
    return [event(ip, "auth", "fail", u, f"{SERVERS[0]}:443") for u in USERS[:n]], \
        {ip: {"password_spray"}}


def brute_force_success(n=6, ip="203.0.113.30", user="root"):
    evs = [event(ip, "auth", "fail", user, f"{SERVERS[1]}:22") for _ in range(n)]
    evs.append(event(ip, "auth", "success", user, f"{SERVERS[1]}:22"))
    # n >= brute_force threshold, so brute_force fires as well -- correctly so
    return evs, {ip: {"brute_force", "brute_force_success"}}


def distributed_brute_force(n=8, user="ceo"):
    ips = [f"198.51.100.{10 + i}" for i in range(n)]
    return [event(ip, "auth", "fail", user, f"{SERVERS[0]}:443") for ip in ips], \
        {f"user:{user}": {"distributed_brute_force"}}


def port_scan(n=25, ip="203.0.113.40", target="10.0.100.3"):
    ports = random.sample(range(1, 10000), n)
    return [event(ip, "network", "denied", None, f"{target}:{p}") for p in ports], \
        {ip: {"port_scan"}}


def host_sweep(n=15, ip="203.0.113.50"):
    return [event(ip, "network", "denied", None, f"10.0.50.{i}:22") for i in range(1, n + 1)], \
        {ip: {"host_sweep"}}


def api_flood(n=80, ip="203.0.113.60"):
    return [event(ip, "api", "success", None, f"{SERVERS[2]}:443") for _ in range(n)], \
        {ip: {"api_flood"}}


def api_access_probing(n=15, ip="203.0.113.70"):
    return [event(ip, "api", random.choice(["denied", "fail"]), None, f"{SERVERS[2]}:443")
            for _ in range(n)], {ip: {"api_access_probing"}}


ATTACKS = {f.__name__: f for f in [brute_force, password_spray, brute_force_success,
                                    distributed_brute_force, port_scan, host_sweep,
                                    api_flood, api_access_probing]}


def normal_event(rng: random.Random) -> dict:
    """Low-rate, benign activity spread over many users and hosts."""
    i = rng.randrange(100)                      # 100 workstations, users shared across a few
    ip, user = f"10.0.0.{10 + i}", USERS[i % len(USERS)]
    kind = rng.choices(["auth", "network", "api"], weights=[3, 4, 3])[0]
    if kind == "auth":
        return event(ip, "auth", "fail" if rng.random() < 0.05 else "success", user,
                     f"{rng.choice(SERVERS)}:22")
    if kind == "network":
        return event(ip, "network", "success" if rng.random() < 0.9 else "denied", None,
                     f"{rng.choice(SERVERS)}:{rng.choice(COMMON_PORTS)}")
    return event(ip, "api", "success" if rng.random() < 0.95 else "fail", user,
                 f"{rng.choice(SERVERS)}:443")


# --- sending --------------------------------------------------------------------

class Sender:
    def __init__(self, api: str, dup_rate: float, late_rate: float, late_by: float, quiet: bool):
        self.url = api.rstrip("/") + "/events"
        self.dup_rate, self.late_rate, self.late_by = dup_rate, late_rate, late_by
        self.quiet = quiet
        self.counts = {"sent": 0, "accepted": 0, "duplicates": 0, "late": 0, "errors": 0}

    def _post(self, ev: dict) -> int:
        req = urllib.request.Request(self.url, data=json.dumps(ev).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except urllib.error.URLError as e:
            sys.exit(f"cannot reach {self.url}: {e.reason} -- is the ingest API running?")

    def send(self, ev: dict) -> None:
        if random.random() < self.late_rate:
            # same event, but stamped as if it happened late_by seconds ago
            at = datetime.fromisoformat(ev["event_time"]) - timedelta(seconds=self.late_by)
            ev = {**ev, "event_id": str(uuid.uuid4()), "event_time": at.isoformat()}
            self.counts["late"] += 1
        code = self._post(ev)
        self.counts["sent"] += 1
        if code == 202:
            self.counts["accepted"] += 1
        else:
            self.counts["errors"] += 1
            if not self.quiet:
                print(f"  ! HTTP {code} for {ev['event_id']}")
        if random.random() < self.dup_rate:
            # at-least-once in action: a retry re-sends the exact same event_id
            self._post(ev)
            self.counts["duplicates"] += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", default="all",
                    help="normal | all | " + " | ".join(ATTACKS) + " (comma-separate several)")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--duration", type=float, default=20, help="seconds of normal background traffic")
    ap.add_argument("--rate", type=float, default=10, help="normal events per second")
    ap.add_argument("--pace", type=float, default=0.02, help="seconds between attack events")
    ap.add_argument("--dup-rate", type=float, default=0.0, help="fraction of events re-sent as duplicates")
    ap.add_argument("--late-rate", type=float, default=0.0, help="fraction of events stamped in the past")
    ap.add_argument("--late-by", type=float, default=300, help="how far in the past late events are")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.list:
        for name, f in ATTACKS.items():
            _, expect = f()
            print(f"{name:<26} -> {', '.join(sorted(set().union(*expect.values())))}")
        print(f"{'normal':<26} -> (no alerts expected)")
        return 0

    if args.seed is not None:
        random.seed(args.seed)
    rng = random.Random(args.seed)
    s = Sender(args.api, args.dup_rate, args.late_rate, args.late_by, args.quiet)

    names = list(ATTACKS) if args.scenario == "all" else \
        [n for n in args.scenario.split(",") if n != "normal"]
    unknown = [n for n in names if n not in ATTACKS]
    if unknown:
        ap.error(f"unknown scenario(s) {unknown}; see --list")
    with_normal = args.scenario in ("all", "normal") or "normal" in args.scenario.split(",")

    # Interleave: normal background throughout, attacks spread across the run.
    start = time.time()
    duration = args.duration if with_normal else 0
    attack_at = {n: start + (i + 1) * duration / (len(names) + 1) for i, n in enumerate(names)}
    next_normal = start
    expected: dict = {}

    while True:
        now = time.time()
        due = [n for n, t in attack_at.items() if t <= now]
        for n in due:
            evs, exp = ATTACKS[n]()
            expected.update(exp)
            if not args.quiet:
                print(f"[{now - start:5.1f}s] attack {n}: {len(evs)} events -> expect "
                      f"{', '.join(sorted(set().union(*exp.values())))}")
            for e in evs:
                s.send(e)
                time.sleep(args.pace)
            del attack_at[n]
        if with_normal and now - start < duration:
            if now >= next_normal:
                s.send(normal_event(rng))
                next_normal += 1 / args.rate
            time.sleep(max(0.0, min(next_normal - time.time(), 0.05)))
        elif not attack_at:
            break

    print(f"\ndone in {time.time() - start:.1f}s: {s.counts}")
    if expected:
        print("expected alerts:")
        for entity, rules in expected.items():
            print(f"  {entity:<22} {', '.join(sorted(rules))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
