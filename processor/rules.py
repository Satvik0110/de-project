"""Detection rules (Lab 3 step 5: "evaluate deterministic rules").

Each rule says which events it looks at, how to group them (the key), what to
measure per group within one window, and the threshold that raises an alert.

Every measure here only grows as events are added to a window: a count, a number
of distinct values, or "N failures then a success". That property is what lets the
engine fire an alert the moment a threshold is crossed instead of waiting for the
window to close, with no risk of having to retract it later.

The set is limited to what our event schema can actually support. Rules needing
fields we do not have (geo-location, bytes transferred) are left out rather than
approximated. Each rule is tagged with its MITRE ATT&CK technique and tactic, which
is what lets alerts from one attacker be read as stages of one intrusion.
"""
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .model import Event

SEVERITIES = ["low", "medium", "high", "critical"]
# A value at this many times the threshold bumps the alert one severity level.
ESCALATE_AT = 3


@dataclass(slots=True)
class KeyState:
    """What one rule has seen for one key, in one pane or one merged window."""
    n: int = 0                               # matching events (failures, for fail_then_success)
    values: set = field(default_factory=set) # distinct values, for 'distinct' rules
    first_ts: float = float("inf")           # earliest counted event_time
    last_ts: float = float("-inf")           # latest event_time of any matching event
    last_ingest_ts: Optional[float] = None   # ingest_time of that latest event
    success_ts: float = float("-inf")        # latest success, for fail_then_success
    sample_ids: list = field(default_factory=list)

    def merge(self, other: "KeyState", cap: int) -> None:
        self.n += other.n
        self.values |= other.values
        self.first_ts = min(self.first_ts, other.first_ts)
        if other.last_ts > self.last_ts:
            self.last_ts, self.last_ingest_ts = other.last_ts, other.last_ingest_ts
        self.success_ts = max(self.success_ts, other.success_ts)
        room = cap - len(self.sample_ids)
        if room > 0:
            self.sample_ids.extend(other.sample_ids[:room])


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    severity: str
    threshold: int
    applies: Callable[[Event], bool]
    key_fields: tuple[str, ...]
    technique: str                           # MITRE ATT&CK id + name
    tactic: str                              # MITRE ATT&CK tactic
    measure: str = "count"                   # count | distinct | fail_then_success
    distinct_of: Optional[Callable[[Event], Any]] = None

    def key(self, ev: Event) -> tuple:
        return tuple(getattr(ev, f) for f in self.key_fields)

    def add(self, st: KeyState, ev: Event, cap: int) -> None:
        if self.measure == "fail_then_success":
            if ev.status == "success":
                st.success_ts = max(st.success_ts, ev.ts)
            else:
                st.n += 1
                st.first_ts = min(st.first_ts, ev.ts)
        else:
            st.n += 1
            st.first_ts = min(st.first_ts, ev.ts)
            if self.measure == "distinct":
                st.values.add(self.distinct_of(ev))
        if ev.ts >= st.last_ts:
            st.last_ts, st.last_ingest_ts = ev.ts, ev.ingest_ts
        if len(st.sample_ids) < cap:
            st.sample_ids.append(ev.event_id)

    def value(self, st: KeyState) -> int:
        if self.measure == "distinct":
            return len(st.values)
        if self.measure == "fail_then_success":
            # only counts once a success follows the first failure
            return st.n if st.success_ts > st.first_ts else 0
        return st.n

    def severity_for(self, value: int) -> str:
        i = SEVERITIES.index(self.severity)
        if value >= ESCALATE_AT * self.threshold:
            i = min(i + 1, len(SEVERITIES) - 1)
        return SEVERITIES[i]


def _threshold(name: str, default: int) -> int:
    return int(os.getenv(f"RULE_{name.upper()}_THRESHOLD", default))


def _auth_fail(ev: Event) -> bool:
    return ev.source_type == "auth" and ev.status != "success"


# Attack-pattern signatures, matched against the decoded request line. They describe
# the payload classes OWASP lists for injection: SQL, OS command, path traversal,
# NoSQL operator, template, script, LDAP filter and header (CRLF) injection.
INJECTION = re.compile("|".join([
    r"'\s*(or|and)\s", r"union\s+select", r"@@version", r"waitfor\s+delay", r"'\s*--",
    r"[;|&]\s*(cat|id|whoami|ping|powershell|wget|curl)\b",
    r"\.\.[/\\]",
    r"\[\$(ne|gt|lt|regex)\]", r"\$where",
    r"\{\{.*\}\}", r"\$\{.*\}",
    r"<script", r"onerror\s*=",
    r"\*\)\(",
    r"[\r\n]",
]), re.IGNORECASE)


def is_injection(ev: Event) -> bool:
    return ev.request is not None and INJECTION.search(ev.request) is not None


def default_rules() -> list[Rule]:
    return [
        # --- authentication ---------------------------------------------------
        Rule(
            name="brute_force",
            description="Repeated failed logins from one source against one account",
            technique="T1110.001 Password Guessing",
            tactic="Credential Access",
            severity="high",
            threshold=_threshold("brute_force", 5),
            applies=_auth_fail,
            key_fields=("src_ip", "user"),
        ),
        Rule(
            name="password_spray",
            description="One source failing logins across many different accounts",
            technique="T1110.003 Password Spraying",
            tactic="Credential Access",
            severity="high",
            threshold=_threshold("password_spray", 5),
            applies=lambda ev: _auth_fail(ev) and ev.user is not None,
            key_fields=("src_ip",),
            measure="distinct",
            distinct_of=lambda ev: ev.user,
        ),
        Rule(
            name="brute_force_success",
            description="Failed logins followed by a successful one: likely compromised account",
            technique="T1078 Valid Accounts",
            tactic="Initial Access",
            severity="critical",
            threshold=_threshold("brute_force_success", 5),
            applies=lambda ev: ev.source_type == "auth",
            key_fields=("src_ip", "user"),
            measure="fail_then_success",
        ),
        Rule(
            name="distributed_brute_force",
            description="One account failing logins from many different sources",
            technique="T1110 Brute Force",
            tactic="Credential Access",
            severity="high",
            threshold=_threshold("distributed_brute_force", 5),
            applies=lambda ev: _auth_fail(ev) and ev.user is not None,
            key_fields=("user",),
            measure="distinct",
            distinct_of=lambda ev: ev.src_ip,
        ),
        # --- network ----------------------------------------------------------
        Rule(
            name="port_scan",
            description="One source probing many ports on one host (vertical scan)",
            technique="T1046 Network Service Discovery",
            tactic="Discovery",
            severity="medium",
            threshold=_threshold("port_scan", 10),
            applies=lambda ev: ev.source_type == "network" and ev.dest_port is not None,
            key_fields=("src_ip", "dest_ip"),
            measure="distinct",
            distinct_of=lambda ev: ev.dest_port,
        ),
        Rule(
            name="connection_flood",
            description="One source opening many connections to one service (resource exhaustion)",
            technique="T1499 Endpoint Denial of Service",
            tactic="Impact",
            severity="medium",
            threshold=_threshold("connection_flood", 30),
            applies=lambda ev: ev.source_type == "network" and ev.dest_port is not None,
            key_fields=("src_ip", "dest_ip", "dest_port"),
        ),
        Rule(
            name="host_sweep",
            description="One source contacting many hosts (horizontal scan)",
            technique="T1046 Network Service Discovery",
            tactic="Discovery",
            severity="medium",
            threshold=_threshold("host_sweep", 10),
            applies=lambda ev: ev.source_type == "network" and ev.dest_ip is not None,
            key_fields=("src_ip",),
            measure="distinct",
            distinct_of=lambda ev: ev.dest_ip,
        ),
        # --- api ----------------------------------------------------------------
        Rule(
            name="injection_probe",
            description="Requests carrying injection payloads (SQLi, command, traversal, template, XSS...)",
            technique="T1190 Exploit Public-Facing Application",
            tactic="Initial Access",
            severity="medium",
            threshold=_threshold("injection_probe", 1),
            applies=is_injection,
            key_fields=("src_ip",),
        ),
        Rule(
            name="api_flood",
            description="Abnormally high API request rate from one source",
            technique="T1499 Endpoint Denial of Service",
            tactic="Impact",
            severity="medium",
            threshold=_threshold("api_flood", 50),
            applies=lambda ev: ev.source_type == "api",
            key_fields=("src_ip",),
        ),
        Rule(
            name="api_access_probing",
            description="Many denied or failed API calls from one source (enumeration / authz probing)",
            technique="T1595 Active Scanning",
            tactic="Reconnaissance",
            severity="medium",
            threshold=_threshold("api_access_probing", 10),
            applies=lambda ev: ev.source_type == "api" and ev.status != "success",
            key_fields=("src_ip",),
        ),
    ]
