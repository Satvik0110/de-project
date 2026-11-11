"""Event-time sliding-window engine. Pure Python, no Kafka, so it can be unit tested.

Implements Lab 3 section 3 in order:
  2. assign each event to windows by its own event_time, not arrival time
  3. a watermark (newest event_time seen minus the allowed lateness) decides when a
     window is complete; events for windows already emitted are dropped as late
  4. a short-lived set of recently seen event_ids discards duplicates
  5. deterministic rules are evaluated per window

How the sliding windows are stored
----------------------------------
A 60 s window that slides every 10 s would put each event in 6 windows. Instead of
copying it 6 times, time is cut into 10 s *panes* and each event is added to exactly
one pane. A window is then just its 6 consecutive panes, merged when needed. Panes
older than every still-open window are evicted, which is what bounds memory even
when events arrive out of order (the FR2 risk in Lab 2).

When alerts fire
----------------
Early: as soon as an event pushes a rule over its threshold in any open window. Every
rule measure only grows, so an early alert is never wrong later. This keeps detection
latency at milliseconds instead of "window length + lateness".
Final: when that window closes, the alert is re-emitted with the same alert_id if its
count grew. The id is deterministic, so a consumer can upsert on it.

While one window has alerted for a (rule, key), overlapping windows for the same
(rule, key) are suppressed; otherwise a single 20 s attack would raise six alerts.
"""
import json
import math
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .model import Event
from .rules import SEVERITIES, KeyState, Rule

# Fixed namespace so the same (rule, key, window) always maps to the same alert_id,
# across restarts and replays.
_ALERT_NS = uuid.UUID("6f1c3e0a-5b7d-4c1e-9a2b-4f6d8e0c1a3b")


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


@dataclass(slots=True)
class SourceAgg:
    """Per-source_type statistics for one pane, for the aggregates output."""
    events: int = 0
    ips: set = field(default_factory=set)
    users: set = field(default_factory=set)
    status: Counter = field(default_factory=Counter)

    def merge(self, other: "SourceAgg") -> None:
        self.events += other.events
        self.ips |= other.ips
        self.users |= other.users
        self.status.update(other.status)


@dataclass(slots=True)
class Pane:
    rules: dict = field(default_factory=dict)       # rule name -> {key: KeyState}
    sources: dict = field(default_factory=dict)     # source_type -> SourceAgg
    min_offset: dict = field(default_factory=dict)  # partition -> lowest offset in this pane


@dataclass(slots=True)
class FiredAlert:
    alert: dict
    count: int
    severity: str


class WindowEngine:
    def __init__(self, rules: list[Rule], window_s: int = 60, slide_s: int = 10,
                 lateness_s: float = 10.0, sample_cap: int = 10, processor_info: Optional[dict] = None):
        if window_s % slide_s:
            raise ValueError("window_s must be a multiple of slide_s")
        self.rules = rules
        self.window_s, self.slide_s, self.lateness_s = window_s, slide_s, lateness_s
        self.k = window_s // slide_s           # panes per window
        self.sample_cap = sample_cap
        self.processor_info = processor_info or {}

        self.panes: dict[int, Pane] = {}
        # Pane index where the earliest not-yet-emitted window starts. Every window
        # starting before it has been emitted; any event in a pane before it is late.
        self.next_start: Optional[int] = None
        self.max_event_ts = float("-inf")
        self.watermark = float("-inf")

        self.seen: dict[str, int] = {}                     # event_id -> pane index
        self.fired: dict[tuple, FiredAlert] = {}           # (rule, key, start) -> alert
        self.last_alert: dict[tuple, tuple[int, int]] = {} # (rule, key) -> (start, end) pane idx
        self.last_offset: dict[int, int] = {}              # partition -> last offset handled
        self.stats: Counter = Counter()

    # ------------------------------------------------------------------ input

    def pane_of(self, ts: float) -> int:
        return math.floor(ts / self.slide_s)

    def note_offset(self, partition: Optional[int], offset: Optional[int]) -> None:
        """Record that an offset was handled (even if the event itself was rejected)."""
        if partition is not None:
            self.last_offset[partition] = max(self.last_offset.get(partition, -1), offset)

    def add(self, ev: Event, now: float, partition: Optional[int] = None,
            offset: Optional[int] = None) -> list[dict]:
        """Ingest one event. Returns any alerts it triggers immediately."""
        self.note_offset(partition, offset)
        p = self.pane_of(ev.ts)

        if self.next_start is not None and p < self.next_start:
            self.stats["late"] += 1          # every window it belongs to is already emitted
            return []
        if ev.event_id in self.seen:
            self.stats["duplicate"] += 1
            return []
        self.seen[ev.event_id] = p
        self.stats["accepted"] += 1

        if self.next_start is None:
            self.next_start = p - self.k + 1  # first window that can contain this event

        pane = self.panes.get(p)
        if pane is None:
            pane = self.panes[p] = Pane()
        if partition is not None:
            pane.min_offset[partition] = min(pane.min_offset.get(partition, offset), offset)

        agg = pane.sources.get(ev.source_type)
        if agg is None:
            agg = pane.sources[ev.source_type] = SourceAgg()
        agg.events += 1
        agg.ips.add(ev.src_ip)
        if ev.user:
            agg.users.add(ev.user)
        agg.status[ev.status] += 1

        out = []
        for rule in self.rules:
            if not rule.applies(ev):
                continue
            key = rule.key(ev)
            states = pane.rules.setdefault(rule.name, {})
            st = states.get(key)
            if st is None:
                st = states[key] = KeyState()
            rule.add(st, ev, self.sample_cap)
            alert = self._check_early(rule, key, p, now, ev)
            if alert:
                out.append(alert)

        if ev.ts > self.max_event_ts:
            self.max_event_ts = ev.ts
            self.watermark = max(self.watermark, ev.ts - self.lateness_s)
        return out

    def advance_wallclock(self, now: float) -> None:
        """Called when the input is idle: let the watermark follow the wall clock."""
        self.watermark = max(self.watermark, now - self.lateness_s)

    def restore(self, closed_before_ts: float) -> None:
        """Resume after a restart: windows starting before this time were already emitted."""
        idx = self.pane_of(closed_before_ts)
        self.next_start = idx if self.next_start is None else max(self.next_start, idx)

    # --------------------------------------------------------------- windows

    def _merged(self, rule: Rule, key: tuple, start: int) -> Optional[KeyState]:
        merged = None
        for i in range(start, start + self.k):
            pane = self.panes.get(i)
            st = pane.rules.get(rule.name, {}).get(key) if pane else None
            if st is None:
                continue
            if merged is None:
                merged = KeyState()
            merged.merge(st, self.sample_cap)
        return merged

    def _check_early(self, rule: Rule, key: tuple, p: int, now: float, ev: Event) -> Optional[dict]:
        """Fire as soon as any open window containing pane p crosses the threshold.

        Windows are tried latest-start first: of all the windows that cross, that one
        covers the most of what is still to come, so its final count is the most useful.
        """
        lo = max(self.next_start, p - self.k + 1)
        for start in range(p, lo - 1, -1):
            fk = (rule.name, key, start)
            fired = self.fired.get(fk)
            if fired is not None:
                # Already alerted for this window: only re-emit if severity escalated.
                st = self._merged(rule, key, start)
                value = rule.value(st)
                if SEVERITIES.index(rule.severity_for(value)) > SEVERITIES.index(fired.severity):
                    self.stats["alerts_escalated"] += 1
                    return self._update(fired, rule, st, value, now, "escalated")
                return None
            if self._suppressed(rule.name, key, start):
                continue
            st = self._merged(rule, key, start)
            value = rule.value(st)
            if value >= rule.threshold:
                return self._fire(rule, key, start, st, value, now, ev)
        return None

    def _suppressed(self, rule_name: str, key: tuple, start: int) -> bool:
        last = self.last_alert.get((rule_name, key))
        return last is not None and start < last[1] and start + self.k > last[0]

    def _fire(self, rule, key, start, st, value, now, ev) -> dict:
        ws, we = start * self.slide_s, (start + self.k) * self.slide_s
        named = dict(zip(rule.key_fields, key))
        entity = ",".join(f"{f}={v}" for f, v in named.items())
        alert = {
            "alert_id": str(uuid.uuid5(_ALERT_NS, f"{rule.name}|{entity}|{ws}|{self.window_s}")),
            "rule_name": rule.name,
            "description": rule.description,
            "severity": rule.severity_for(value),
            "entity": entity,
            "src_ip": named.get("src_ip"),
            "user": named.get("user"),
            "dest_ip": named.get("dest_ip"),
            "window_start": iso(ws),
            "window_end": iso(we),
            "count": value,
            "threshold": rule.threshold,
            "trigger": "early",
            "event_time": iso(st.last_ts),
            "first_event_time": iso(st.first_ts),
            "sample_event_ids": list(st.sample_ids),
            "trigger_event_id": ev.event_id,
            "detected_at": iso(now),
            "detection_latency_ms": round((now - ev.ingest_ts) * 1000, 1) if ev.ingest_ts else None,
            "processor": self.processor_info,
        }
        self.fired[(rule.name, key, start)] = FiredAlert(alert, value, alert["severity"])
        self.last_alert[(rule.name, key)] = (start, start + self.k)
        self.stats["alerts"] += 1
        return dict(alert)

    def _update(self, fired: FiredAlert, rule, st, value, now, trigger) -> dict:
        fired.count, fired.severity = value, rule.severity_for(value)
        fired.alert.update(
            count=value, severity=fired.severity, trigger=trigger,
            event_time=iso(st.last_ts), first_event_time=iso(st.first_ts),
            sample_event_ids=list(st.sample_ids), detected_at=iso(now),
        )
        return dict(fired.alert)

    def close_ready(self, now: float) -> tuple[list[dict], list[dict]]:
        """Emit every window whose end the watermark has passed.

        Returns (final alert updates, aggregate rows).
        """
        alerts, aggregates = [], []
        if self.next_start is None:
            return alerts, aggregates

        while (self.next_start + self.k) * self.slide_s <= self.watermark:
            if not self.panes:
                # Nothing buffered: jump straight to the first window still open.
                self.next_start = max(self.next_start, self.pane_of(self.watermark) - self.k + 1)
                self._evict()
                break
            lowest = min(self.panes)
            if lowest >= self.next_start + self.k:
                # Gap in the data: skip the empty windows in one step.
                self.next_start = lowest - self.k + 1
                self._evict()
                continue
            alerts += self._close_window(self.next_start, now)
            aggregates += self._aggregates(self.next_start)
            self.next_start += 1
            self.stats["windows_closed"] += 1
            self._evict()
        return alerts, aggregates

    def _close_window(self, start: int, now: float) -> list[dict]:
        out = []
        for fk in [fk for fk in self.fired if fk[2] == start]:
            fired = self.fired.pop(fk)
            rule = next(r for r in self.rules if r.name == fk[0])
            st = self._merged(rule, fk[1], start)
            value = rule.value(st)
            if value > fired.count:
                out.append(self._update(fired, rule, st, value, now, "final"))
        return out

    def _aggregates(self, start: int) -> list[dict]:
        """Per source_type stats, emitted once per non-overlapping (tumbling) window."""
        if start % self.k:
            return []
        merged: dict[str, SourceAgg] = {}
        for i in range(start, start + self.k):
            pane = self.panes.get(i)
            for src, agg in (pane.sources.items() if pane else ()):
                merged.setdefault(src, SourceAgg()).merge(agg)
        ws, we = start * self.slide_s, (start + self.k) * self.slide_s
        return [{
            "window_start": iso(ws),
            "window_end": iso(we),
            "source_type": src,
            "event_count": agg.events,
            "unique_ips": len(agg.ips),
            "unique_users": len(agg.users),
            "success_count": agg.status["success"],
            "fail_count": agg.status["fail"],
            "denied_count": agg.status["denied"],
            "processor": self.processor_info,
        } for src, agg in sorted(merged.items())]

    def _evict(self) -> None:
        for i in [i for i in self.panes if i < self.next_start]:
            del self.panes[i]
        # A duplicate of an id from an evicted pane would be dropped as late anyway.
        for eid in [e for e, i in self.seen.items() if i < self.next_start]:
            del self.seen[eid]
        # No future window can overlap an alert window that ended before next_start.
        for k in [k for k, (_, end) in self.last_alert.items() if end <= self.next_start]:
            del self.last_alert[k]

    # ------------------------------------------------------- offsets / state

    def committable_offsets(self) -> dict[int, int]:
        """Offset to commit per partition: nothing still sitting in an open window.

        If the process dies, it resumes from here and rebuilds every open window from
        Kafka. Committing past a buffered event would lose it on restart.
        """
        out = {}
        for part, last in self.last_offset.items():
            pending = [pane.min_offset[part] for pane in self.panes.values() if part in pane.min_offset]
            out[part] = min(pending) if pending else last + 1
        return out

    def checkpoint(self) -> str:
        """Small state stored as commit metadata, read back by restore()."""
        if self.next_start is None:
            return ""
        return json.dumps({"closed_before": self.next_start * self.slide_s,
                           "window_s": self.window_s, "slide_s": self.slide_s})

    def state_size(self) -> dict:
        return {"open_panes": len(self.panes), "dedup_ids": len(self.seen),
                "open_alerts": len(self.fired)}
