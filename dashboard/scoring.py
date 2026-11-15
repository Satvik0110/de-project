"""Detection scoreboard: grade detection against the simulator's ground truth.

Attribution: an alert belongs to a campaign if it names one of the campaign's source IPs
(or its target account, for per-user rules) and was first raised between the campaign
start and GRACE after its end. Alerts on malicious campaigns are true positives; alerts on
benign campaigns (legitimate activity that looks hostile) or on nothing at all are false
positives. Recall counts only finished malicious campaigns.

Per campaign it also measures what precision/recall cannot:
  ttd_ms                 campaign start -> first expected alert
  progress_at_detection  share of the attack's events that had already happened when the
                         first alert fired -- an analytical query over the Parquet lake,
                         pruned to the hour partitions the campaign spans
  early_by_s             how long before the window would have closed the alert fired, i.e.
                         what alerting early buys over alerting at window close
"""
import statistics
from datetime import timedelta, timezone

import pyarrow.compute as pc
import pyarrow.dataset as ds

from lake.writer import LAKE_DIR

GRACE = timedelta(seconds=120)
_progress_cache: dict[str, tuple] = {}      # campaign_id -> (events, events_before_alert), once final


def _median(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def attack_events(ips: list[str], start, end, first_alert) -> tuple[int, int] | None:
    """(events, events ingested before the first alert) for a campaign, from the lake."""
    # partitions are UTC hours; Postgres hands back session-local times, so normalise first
    lo, hi = (start - timedelta(seconds=5)).astimezone(timezone.utc), (end + timedelta(seconds=5)).astimezone(timezone.utc)
    hours, t = [], lo.replace(minute=0, second=0, microsecond=0)
    while t <= hi:
        hours.append(t)
        t += timedelta(hours=1)
    part = None
    for h in hours:                      # partition pruning: only these hour folders are opened
        f = (ds.field("year") == h.year) & (ds.field("month") == h.month) & \
            (ds.field("day") == h.day) & (ds.field("hour") == h.hour)
        part = f if part is None else part | f
    try:
        table = ds.dataset(LAKE_DIR, format="parquet", partitioning="hive").to_table(
            columns=["event_id", "ingest_time"],
            filter=part & ds.field("src_ip").isin(ips) & (ds.field("event_time") >= lo) & (ds.field("event_time") <= hi))
    except (FileNotFoundError, ValueError):
        return None
    ids = table.column("event_id").to_pylist()
    before = pc.sum(pc.less_equal(table.column("ingest_time"), first_alert)).as_py() if first_alert else 0
    return len(set(ids)), before or 0       # lake is at-least-once: count distinct event_ids


def score(camps: list[dict], alerts: list[dict], lake_newest, events_total: int) -> dict:
    attributed: dict[int, dict] = {}
    out = []
    for c in camps:
        ips, end = set(c["ips"]), c["ended_at"]
        hits = [a for a in alerts
                if (a["src_ip"] in ips or (a["src_ip"] is None and a["username"] == c["target_user"]))
                and c["started_at"] <= a["first_detected_at"] <= (end or a["first_detected_at"]) + GRACE]
        for a in hits:
            attributed[id(a)] = c
        row = {"campaign_id": str(c["campaign_id"]), "scenario": c["scenario"], "malicious": c["malicious"],
               "started_at": c["started_at"], "ended_at": end, "attacker_ips": c["ips"],
               "expected_rules": c["expected_rules"], "detected_rules": [], "missed_rules": [],
               "detected": False, "ttd_ms": None, "attack_events": c["requests"],
               "progress_at_detection": None, "early_by_s": None, "fp_alerts": 0, "note": None}
        if not c["malicious"]:
            row["fp_alerts"] = len(hits)
            row["note"] = (f"benign, but raised {', '.join(sorted({a['rule_name'] for a in hits}))}"
                           if hits else "benign: correctly ignored")
            out.append(row)
            continue

        expected = set(c["expected_rules"])
        exp_hits = sorted((a for a in hits if a["rule_name"] in expected), key=lambda a: a["first_detected_at"])
        row["detected_rules"] = sorted({a["rule_name"] for a in exp_hits})
        row["missed_rules"] = [r for r in c["expected_rules"] if r not in row["detected_rules"]]
        row["detected"] = bool(exp_hits)
        if exp_hits:
            first = exp_hits[0]
            row["ttd_ms"] = round((first["first_detected_at"] - c["started_at"]).total_seconds() * 1000)
            lateness = (first["raw"].get("processor") or {}).get("lateness_s", 10)
            row["early_by_s"] = round((first["window_end"] + timedelta(seconds=lateness)
                                       - first["first_detected_at"]).total_seconds(), 1)
        if end is None:
            row["note"] = "running"
        elif row["missed_rules"]:
            row["note"] = ("missed: paced below the per-window threshold (evaded)" if c["scenario"] == "low_and_slow"
                           else f"missed: {', '.join(row['missed_rules'])}")

        # progress at detection: final once the lake holds data past the campaign's end
        cid = row["campaign_id"]
        if cid not in _progress_cache and end is not None and lake_newest and lake_newest > end + timedelta(seconds=5):
            res = attack_events(c["ips"], c["started_at"], end, exp_hits[0]["first_detected_at"] if exp_hits else None)
            if res and res[0]:
                _progress_cache[cid] = res
        if cid in _progress_cache:
            n, before = _progress_cache[cid]
            row["attack_events"] = n
            row["progress_at_detection"] = round(before / n, 3) if exp_hits else None
        out.append(row)

    tp = [a for a in alerts if id(a) in attributed and attributed[id(a)]["malicious"]]
    fps = [{**a["view"], "reason": f"benign {attributed[id(a)]['scenario']}" if id(a) in attributed else "unattributed"}
           for a in alerts if not (id(a) in attributed and attributed[id(a)]["malicious"])]
    mal_done = [r for r in out if r["malicious"] and r["ended_at"] is not None]
    expected_n = sum(len(r["expected_rules"]) for r in mal_done)

    by = {}
    for r in out:
        by.setdefault(r["scenario"], []).append(r)
    by_scenario = [{"scenario": s, "malicious": rs[0]["malicious"], "campaigns": len(rs),
                    "detected": sum(r["detected"] for r in rs),
                    "median_ttd_ms": _median([r["ttd_ms"] for r in rs]),
                    "median_progress": _median([r["progress_at_detection"] for r in rs]),
                    "median_early_by_s": _median([r["early_by_s"] for r in rs]),
                    "fp_alerts": sum(r["fp_alerts"] for r in rs)} for s, rs in by.items()]

    return {
        "funnel": {"events_total": events_total,
                   "attack_events": sum(r["attack_events"] or 0 for r in out if r["malicious"]),
                   "alerts": len(tp), "incidents": len({a["incident_id"] for a in tp if a["incident_id"]})},
        "mttd_ms": _median([r["ttd_ms"] for r in out if r["malicious"]]),
        "malicious_campaigns": len(mal_done), "detected_campaigns": sum(r["detected"] for r in mal_done),
        "recall": sum(len(r["detected_rules"]) for r in mal_done) / expected_n if expected_n else None,
        "precision": len(tp) / len(alerts) if alerts else None,
        "alerts_total": len(alerts), "true_positive_alerts": len(tp), "false_positive_alerts": len(fps),
        "by_scenario": by_scenario, "campaigns": out[:50], "false_positives": fps[:50],
    }
