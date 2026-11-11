"""Parse, validate and normalise one raw Kafka record into an Event.

This is step 1 of Lab 3's processor ("parse + validate fields"). The ingest API has
already validated the payload, but the processor does not trust that: anything
can be written to a Kafka topic, and a replay may carry records from an older
API version. The same Pydantic contract is reused so the two can never disagree.
"""
import ipaddress
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote_plus

from pydantic import ValidationError

from ingest.schema import SecurityEvent


class InvalidEvent(ValueError):
    """The record cannot be processed. The message says why, and goes to the DLQ."""


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    ts: float                    # event_time, epoch seconds (UTC)
    ingest_ts: Optional[float]   # ingest_time, epoch seconds; None if absent
    source_type: str             # auth | network | api
    src_ip: str
    status: str                  # success | fail | denied
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    user: Optional[str] = None
    request: Optional[str] = None  # decoded "path?query" of an HTTP request (api/auth events)


def _canonical_ip(value: str, field: str) -> str:
    """Normalise an IP so that ' 10.0.0.5' or 'FE80::1' vs 'fe80::1' do not split one attacker in two."""
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        raise InvalidEvent(f"{field} is not a valid IP address: {value!r}") from None


def split_dest(dest: Optional[str]) -> tuple[Optional[str], Optional[int]]:
    """Split dest_ip_port into (ip, port).

    Accepts 'ip:port', '[v6]:port', or a bare IP with no port. A bare IPv6 address
    has many colons and is taken as an IP without a port.
    """
    if dest is None or not dest.strip():
        return None, None
    dest = dest.strip()
    if dest.startswith("["):
        host, _, rest = dest[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif dest.count(":") == 1:
        host, _, port = dest.partition(":")
    else:
        host, port = dest, ""

    ip = _canonical_ip(host, "dest_ip_port")
    if not port:
        return ip, None
    if not port.isdigit() or not 0 <= int(port) <= 65535:
        raise InvalidEvent(f"dest_ip_port has an invalid port: {dest!r}")
    return ip, int(port)


def parse_event(raw: bytes, now: float, max_future_s: float) -> Event:
    """Turn a Kafka record value into an Event, or raise InvalidEvent."""
    try:
        ev = SecurityEvent.model_validate_json(raw)
    except ValidationError as exc:
        errors = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise InvalidEvent(f"schema: {errors}") from None

    ts = ev.event_time.timestamp()
    if ts > now + max_future_s:
        raise InvalidEvent(
            f"event_time is {ts - now:.0f}s in the future (limit {max_future_s:.0f}s); "
            "source clock is likely wrong"
        )

    dest_ip, dest_port = split_dest(ev.dest_ip_port)
    user = ev.user.strip().lower() if ev.user and ev.user.strip() else None

    # raw_payload is free-form, but the web server logs its request line there. Decode it
    # once here so rules match what the server actually received, not its URL encoding.
    raw = ev.raw_payload or {}
    request = None
    if isinstance(raw.get("path"), str):
        query = raw.get("query") if isinstance(raw.get("query"), str) else ""
        request = unquote_plus(raw["path"] + ("?" + query if query else ""))

    return Event(
        event_id=str(ev.event_id),
        ts=ts,
        ingest_ts=ev.ingest_time.timestamp() if ev.ingest_time else None,
        source_type=ev.source_type.value,
        src_ip=_canonical_ip(ev.src_ip, "src_ip"),
        status=ev.status.value,
        dest_ip=dest_ip,
        dest_port=dest_port,
        user=user,
        request=request,
    )
