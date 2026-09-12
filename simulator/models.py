import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Literal, List
from pydantic import BaseModel, Field

SourceType = Literal["auth", "network", "api"]
EventStatus = Literal["ok", "invalid", "success", "fail", "denied"]

class SecurityEvent(BaseModel):
    """
    Raw Security Event schema conforming exactly to Figure 2 of the
    'Data Model for the Real-Time Cybersecurity Event Analytics Platform'.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_time: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    ingest_time: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source_type: SourceType
    src_ip: str
    dest_ip_port: str = Field(alias="dest_ip:port")
    user: Optional[str] = None
    status: EventStatus
    raw_payload: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
                "event_time": "2026-09-08T10:15:30.123456+00:00",
                "ingest_time": "2026-09-08T10:15:30.125000+00:00",
                "source_type": "auth",
                "src_ip": "192.168.1.100",
                "dest_ip:port": "10.0.0.5:22",
                "user": "root",
                "status": "fail",
                "raw_payload": {
                    "protocol": "ssh",
                    "auth_method": "password",
                    "attempt_count": 1
                }
            }
        }

class SimulatorConfig(BaseModel):
    """Configuration for active simulator operation."""
    running: bool = False
    events_per_second: float = 10.0
    attack_ratio: float = 0.3           # 30% attacks, 70% normal — realistic mixed traffic
    only_attacks: bool = False          # Mix normal baseline events with attacks for realistic signal-to-noise
    active_scenario: str = "all"        # fallback for backwards compatibility
    selected_scenarios: List[str] = Field(default_factory=lambda: [
        "auth_brute_force",
        "auth_jwt_tampering",
        "api_injection_probe",
        "api_rate_limit",
        "network_port_scan",
        "network_slowloris",
    ])
    target_base_url: str = "http://localhost:8002"  # URL of the target web app being attacked
    target_ip: str = "10.0.0.5"         # Display field — shown in frontend (not used by attack engine)
    target_user: str = "admin"          # Target user account for auth brute-force
    target_api_url: str = "http://localhost:8000/api/v1/events"  # Downstream event API (Kafka producer)
    forward_to_target: bool = False     # Forward events over HTTP to the downstream event API
    inject_late_watermark: bool = False # Intentionally inject 10s-15s late events (stream processor test)
    inject_duplicates: bool = False      # Intentionally emit duplicate event_ids (dedup test)

class AttackTriggerRequest(BaseModel):
    """Request to trigger an explicit attack burst."""
    scenario: Literal[
        "auth_brute_force",
        "auth_jwt_tampering",
        "api_injection_probe",
        "api_rate_limit",
        "network_port_scan",
        "network_slowloris",
        "api_sql_injection",   # legacy alias — maps to api_injection_probe
    ]
    burst_count: int = 50
    target_user: Optional[str] = None  # override for auth attacks
    target_ip: Optional[str] = None    # legacy field, kept for frontend compat


