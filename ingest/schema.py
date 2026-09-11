"""Event contract, as Pydantic models. Mirrors contracts/event.schema.json (Lab 3 section 4)."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import SCHEMA_VERSION


class SourceType(str, Enum):
    auth = "auth"
    network = "network"
    api = "api"


class Status(str, Enum):
    success = "success"
    fail = "fail"
    denied = "denied"


class SecurityEvent(BaseModel):
    """What the Attack Simulator sends us.

    `extra="forbid"` means an unexpected field is a validation error, not something
    silently dropped. That is deliberate: a schema drift in the simulator should show
    up here at ingest, not three layers down as a broken warehouse insert.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = SCHEMA_VERSION
    event_id: UUID
    event_time: datetime
    source_type: SourceType
    src_ip: str
    status: Status
    dest_ip_port: Optional[str] = None
    user: Optional[str] = None
    raw_payload: Optional[dict[str, Any]] = None

    # Stamped by us on arrival; whatever the client sends here is ignored.
    ingest_time: Optional[datetime] = Field(default=None, exclude=True)

    @field_validator("event_time")
    @classmethod
    def require_timezone(cls, v: datetime) -> datetime:
        """Reject naive timestamps.

        A timestamp without an offset is ambiguous, and event-time windows built on
        ambiguous timestamps are silently wrong. Better to fail at the door.
        """
        if v.tzinfo is None:
            raise ValueError(
                "event_time must include an explicit UTC offset "
                "(e.g. 2026-09-11T22:30:00Z or 2026-09-11T22:30:00+05:30)"
            )
        return v

    @field_validator("schema_version")
    @classmethod
    def known_version(cls, v: int) -> int:
        if v != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {v}, this API speaks {SCHEMA_VERSION}")
        return v

    def to_kafka_dict(self) -> dict[str, Any]:
        """Serialisable form, with ingest_time stamped server-side."""
        d = self.model_dump(mode="json")
        d["ingest_time"] = datetime.now(timezone.utc).isoformat()
        return d
