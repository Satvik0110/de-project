"""
HTTP Attack Engine.

Sends genuine HTTP requests to the target web application and builds SecurityEvents
from the response status codes.

Only 2 outcomes exist across the system:
  200 / 201 → status "ok"
  401 / other → status "invalid"

Target API has no 403 or 429 built-in security guards.
Authentication brute-force has an exact 1-in-1000 probability of drawing the correct combo.
"""

import asyncio
import base64
import json
import random
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from urllib.parse import urlparse

import httpx

from simulator.models import SecurityEvent, EventStatus


logger = logging.getLogger("simulator.attack_engine")

# ── Attacker identity pools ───────────────────────────────────────────────────
ATTACKER_IPS = [
    "185.220.101.5", "194.26.29.112", "45.154.255.88",

    "103.251.167.20", "91.240.118.172", "198.51.100.42",
]
SPRAY_IPS = ["194.26.29.112", "91.240.118.172", "103.251.167.20"]
CORP_SUBNETS = ["10.10.1.", "10.10.2.", "172.16.5.", "172.16.8."]

# ── Usernames the attacker attempts ──────────────────────────────────────────
ALL_USERNAMES = [
    "admin", "root", "administrator", "sysadmin",
    "deploy", "alice", "bob", "guest", "user", "test",
    "service_account", "operator", "dbadmin", "support", "analyst"
]

# ── Target Correct Credentials ────────────────────────────────────────────────
CORRECT_CREDENTIALS = {
    "admin":         "Admin@1234",
    "root":          "t00r",
    "administrator": "P@ssw0rd!",
    "sysadmin":      "Sysadmin99",
    "deploy":        "deploy123",
    "alice":         "alice2026",
    "bob":           "bob_secure",
}

# ── Large Brute Force Dataset (1,200+ distinct realistic passwords) ───────────
_BASE_WORDS = [
    "password", "admin", "welcome", "login", "pass", "root", "master", "system",
    "shadow", "dragon", "summer", "winter", "spring", "autumn", "server", "oracle",
    "cisco", "guest", "access", "secure", "secret", "hunter", "flower", "monkey",
    "orange", "yellow", "purple", "diamond", "coffee", "portal", "matrix", "doctor",
    "starwars", "superman", "batman", "alpha", "bravo", "charlie", "delta", "echo",
    "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
    "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform", "victor",
    "whiskey", "xray", "yankee", "zulu"
]
_SUFFIXES = ["123", "1234", "!", "@123", "2024", "2025", "2026", "99", "1", "2026!"]

WORDLIST: List[str] = []
for _w in _BASE_WORDS:
    for _s in _SUFFIXES:
        WORDLIST.append(f"{_w}{_s}")
        WORDLIST.append(f"{_w.capitalize()}{_s}")

# Ensure unique and populated
WORDLIST = list(set(WORDLIST))

# ── Valid credentials for normal baseline traffic ─────────────────────────────
VALID_CREDENTIALS = {
    "alice": "alice2026",
    "bob":   "bob_secure",
}

# ── Injection payloads ────────────────────────────────────────────────────────
INJECTION_PAYLOADS: List[Tuple[str, str, str]] = [
    (
        "/api/search?q=' OR '1'='1' --",
        "sqli",
        "SQL Injection probe",
    ),
    (
        "/api/search?q=../../../../etc/passwd",
        "path_traversal",
        "Directory traversal attempt",
    ),
    (
        "/api/search?q=admin[$ne]=x",
        "nosql_injection",
        "NoSQL operator injection probe",
    ),
    (
        "/api/search?q=id;cat%20/etc/shadow",
        "rce_probe",
        "Remote command execution probe",
    ),
]

# ── Benign search queries for normal API traffic ──────────────────────────────
BENIGN_QUERIES = [
    "monthly+report", "user+list", "inventory",
    "orders+2026", "dashboard+stats", "product+catalog",
]

# ── BOLA Object targets ───────────────────────────────────────────────────────
BOLA_DOCUMENTS = ["1001", "1002", "1003", "1004", "1005", "2048", "3099", "4096", "5120"]

# ── JWT Tampering Templates ───────────────────────────────────────────────────
JWT_TAMPER_SCENARIOS = [
    {
        "technique": "alg_none_bypass",
        "header": {"alg": "none", "typ": "JWT"},
        "claims": {"sub": "admin", "role": "superuser", "is_admin": True},
        "has_signature": False,
    },
    {
        "technique": "privilege_claim_tampering",
        "header": {"alg": "HS256", "typ": "JWT"},
        "claims": {"sub": "alice", "role": "root", "permissions": ["users:write", "system:manage"]},
        "has_signature": True,
    },
    {
        "technique": "expired_token_reuse",
        "header": {"alg": "HS256", "typ": "JWT"},
        "claims": {"sub": "sysadmin", "exp": 1577836800, "role": "admin"},
        "has_signature": True,
    },
    {
        "technique": "tenant_id_manipulation",
        "header": {"alg": "HS256", "typ": "JWT"},
        "claims": {"sub": "guest", "tenant_id": "corporate_master", "is_superuser": True},
        "has_signature": True,
    },
]


def _build_tampered_jwt(scenario: dict) -> str:
    h_b64 = base64.urlsafe_b64encode(json.dumps(scenario["header"]).encode()).decode().rstrip("=")
    c_b64 = base64.urlsafe_b64encode(json.dumps(scenario["claims"]).encode()).decode().rstrip("=")
    if not scenario["has_signature"]:
        return f"{h_b64}.{c_b64}."
    sig_b64 = base64.urlsafe_b64encode(b"invalid_forged_signature_hash").decode().rstrip("=")
    return f"{h_b64}.{c_b64}.{sig_b64}"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _corp_ip() -> str:
    return f"{random.choice(CORP_SUBNETS)}{random.randint(2, 254)}"


def _dest_from_url(base_url: str) -> str:
    """Extract host:port string from a base URL for use in dest_ip_port field."""
    parsed = urlparse(base_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.hostname}:{port}"


def _status_from_http(code: int) -> EventStatus:
    """
    Only 2 outcomes across the entire platform:
      200, 201 → "ok"
      401, other → "invalid"
    """
    if code in (200, 201):
        return "ok"
    return "invalid"


def _build_auth_event(
    resp: httpx.Response,
    src_ip: str,
    base_url: str,
    username: str,
    password_tried: str,
    attack_type: str,
    is_attack: bool,
) -> SecurityEvent:
    status = _status_from_http(resp.status_code)
    ts = _ts()
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_time=ts,
        ingest_time=ts,
        source_type="auth",
        src_ip=src_ip,
        dest_ip_port=_dest_from_url(base_url),
        user=username,
        status=status,
        raw_payload={
            "attack_type": attack_type,
            "http_status": resp.status_code,
            "auth_method": "password",
            "password_tried": password_tried[:3] + "***",
            "failure_reason": None if status == "ok" else "invalid_credentials",
            "threat_flag": "malicious" if is_attack else "benign",
            "severity": (
                "CRITICAL" if (is_attack and status == "ok")
                else "HIGH" if is_attack
                else None
            ),
        },
    )


def _build_jwt_event(
    resp: httpx.Response,
    src_ip: str,
    base_url: str,
    username: str,
    technique: str,
    header: dict,
    claims: dict,
    is_attack: bool,
) -> SecurityEvent:
    status = _status_from_http(resp.status_code)
    ts = _ts()
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_time=ts,
        ingest_time=ts,
        source_type="auth",
        src_ip=src_ip,
        dest_ip_port=_dest_from_url(base_url),
        user=username,
        status=status,
        raw_payload={
            "attack_type": "jwt_token_tampering",
            "http_status": resp.status_code,
            "auth_method": "jwt_bearer",
            "technique": technique,
            "jwt_header": header,
            "jwt_claims": claims,
            "failure_reason": None if status == "ok" else "invalid_token_signature",
            "threat_flag": "malicious" if is_attack else "benign",
            "severity": (
                "CRITICAL" if (is_attack and status == "ok")
                else "HIGH" if is_attack
                else None
            ),
        },
    )


def _build_api_event(
    resp: httpx.Response,
    src_ip: str,
    base_url: str,
    endpoint: str,
    http_method: str,
    attack_type: str,
    signature: Optional[str],
    description: Optional[str],
    is_attack: bool,
    user: Optional[str] = None,
) -> SecurityEvent:
    status = _status_from_http(resp.status_code)
    ts = _ts()
    payload: dict = {
        "attack_type": attack_type,
        "http_method": http_method,
        "endpoint": endpoint,
        "response_code": resp.status_code,
        "threat_flag": "malicious" if is_attack else "benign",
    }
    if signature:
        payload["signature"] = signature
    if description:
        payload["description"] = description
    if is_attack:
        payload["severity"] = "MEDIUM"

    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_time=ts,
        ingest_time=ts,
        source_type="api",
        src_ip=src_ip,
        dest_ip_port=_dest_from_url(base_url),
        user=user or ("anonymous" if is_attack else None),
        status=status,
        raw_payload=payload,
    )


# ── Network Probing Ports ─────────────────────────────────────────────────────
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]


def _build_network_event(
    src_ip: str,
    dest_ip_port: str,
    attack_type: str,
    protocol: str,
    status: EventStatus,
    payload_details: dict,
    is_attack: bool,
) -> SecurityEvent:
    ts = _ts()
    payload = {
        "attack_type": attack_type,
        "protocol": protocol,
        "threat_flag": "malicious" if is_attack else "benign",
        **payload_details,
    }
    if is_attack:
        payload["severity"] = "HIGH"

    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_time=ts,
        ingest_time=ts,
        source_type="network",
        src_ip=src_ip,
        dest_ip_port=dest_ip_port,
        user=None,
        status=status,
        raw_payload=payload,
    )


class ScenarioEngine:

    """
    HTTP Attack Engine.

    Manages persistent async HTTP client against the target web application.
    """

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """Open the shared async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(5.0),
                follow_redirects=True,
            )
            logger.info("Attack engine HTTP client started.")

    async def stop(self):
        """Close the shared async HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            logger.info("Attack engine HTTP client stopped.")

    def _client_or_raise(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(5.0),
                follow_redirects=True,
            )
        return self._client


    # ── Auth attacks ──────────────────────────────────────────────────────────

    async def generate_auth_brute_force(
        self,
        target_url: str = "http://localhost:8002",
        target_user: str = "admin",
        **_,
    ) -> SecurityEvent:
        """
        Send POST /login with a password from the large dataset.
        Exactly 1 in 1000 attempts (0.001 probability) uses the correct password.
        """
        client = self._client_or_raise()
        attacker_ip = random.choice(ATTACKER_IPS)

        # Exactly 1 in 1000 chance to hit the correct combo
        if random.random() < 0.001:
            password = CORRECT_CREDENTIALS.get(target_user, "Admin@1234")
        else:
            password = random.choice(WORDLIST)

        try:
            resp = await client.post(
                f"{target_url}/login",
                json={"username": target_user, "password": password},
            )
        except Exception as exc:
            logger.warning(f"brute_force HTTP error: {exc}")
            resp = httpx.Response(503)

        logger.debug(
            f"BRUTE_FORCE  user={target_user!r}  pwd={password[:3]}***  "
            f"→ HTTP {resp.status_code}"
        )
        return _build_auth_event(
            resp, attacker_ip, target_url,
            target_user, password, "ssh_brute_force", is_attack=True,
        )

    async def generate_auth_jwt_tampering(
        self,
        target_url: str = "http://localhost:8002",
        target_user: str = "admin",
        **_,
    ) -> SecurityEvent:
        """
        Send GET /api/protected with forged/tampered JWT Authorization header.
        Target checks signature, returns 401 Unauthorized (status: 'invalid').
        """
        client = self._client_or_raise()
        attacker_ip = random.choice(ATTACKER_IPS)
        scenario = random.choice(JWT_TAMPER_SCENARIOS)
        token = _build_tampered_jwt(scenario)
        username = scenario["claims"].get("sub", target_user)

        try:
            resp = await client.get(
                f"{target_url}/api/protected",
                headers={"Authorization": f"Bearer {token}"},
            )
        except Exception as exc:
            logger.warning(f"jwt HTTP error: {exc}")
            resp = httpx.Response(503)

        logger.debug(
            f"JWT_TAMPER  tech={scenario['technique']!r}  user={username!r}  "
            f"→ HTTP {resp.status_code}"
        )
        return _build_jwt_event(
            resp, attacker_ip, target_url,
            username, scenario["technique"], scenario["header"], scenario["claims"],
            is_attack=True,
        )

    # ── API attacks (2 scenarios) ─────────────────────────────────────────────

    async def generate_api_injection_probe(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """
        Send GET /api/search with an injection payload in the query string.
        Target has no prevention rules, so it returns 200 OK (status: 'ok').
        """
        client = self._client_or_raise()
        attacker_ip = random.choice(ATTACKER_IPS)
        endpoint, signature, description = random.choice(INJECTION_PAYLOADS)

        try:
            resp = await client.get(f"{target_url}{endpoint}")
        except Exception as exc:
            logger.warning(f"injection HTTP error: {exc}")
            resp = httpx.Response(503)

        logger.debug(
            f"INJECTION  sig={signature!r}  → HTTP {resp.status_code}"
        )
        return _build_api_event(
            resp, attacker_ip, target_url,
            endpoint, "GET", "api_injection_probe",
            signature, description, is_attack=True,
        )

    async def generate_api_rate_limit(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """
        Send POST /api/export to flood export endpoint.
        Target has no rate limiter, returns 200 OK (status: 'ok').
        """
        client = self._client_or_raise()
        attacker_ip = "45.154.255.88"
        endpoint = "/api/export"

        try:
            resp = await client.post(
                f"{target_url}{endpoint}",
                json={"format": "csv"},
            )
        except Exception as exc:
            logger.warning(f"rate_limit HTTP error: {exc}")
            resp = httpx.Response(503)

        logger.debug(f"RATE_LIMIT  → HTTP {resp.status_code}")
        return _build_api_event(
            resp, attacker_ip, target_url,
            endpoint, "POST", "rate_limit_exhaustion",
            None, None, is_attack=True,
        )

    # ── Network attacks (2 scenarios) ─────────────────────────────────────────

    async def generate_network_port_scan(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """
        Simulate TCP SYN port scanning across common administrative/service ports.
        Attempts connection or socket probe against the target host.
        """
        attacker_ip = random.choice(ATTACKER_IPS)
        parsed = urlparse(target_url)
        target_host = parsed.hostname or "127.0.0.1"
        port = random.choice(SCAN_PORTS)
        dest_str = f"{target_host}:{port}"

        # Real TCP probe with ultra-short timeout to observe port state
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, port),
                timeout=0.15
            )
            writer.close()
            await writer.wait_closed()
            status: EventStatus = "ok"
            tcp_state = "OPEN"
        except Exception:
            status = "invalid"
            tcp_state = "CLOSED_OR_FILTERED"

        logger.debug(f"PORT_SCAN  dest={dest_str}  state={tcp_state}  → status={status}")
        return _build_network_event(
            src_ip=attacker_ip,
            dest_ip_port=dest_str,
            attack_type="port_scan_sweep",
            protocol="tcp",
            status=status,
            payload_details={
                "port_probed": port,
                "tcp_flags": "SYN",
                "probe_technique": "stealth_syn_scan",
                "port_state": tcp_state,
                "description": f"Horizontal and vertical port probe on port {port} ({tcp_state})",
            },
            is_attack=True,
        )

    async def generate_network_slowloris(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """
        Simulate Slowloris HTTP header starvation attack holding socket connections open.
        """
        attacker_ip = random.choice(ATTACKER_IPS)
        client = self._client_or_raise()
        dest_str = _dest_from_url(target_url)

        try:
            await client.get(
                f"{target_url}/api/search?q=slowloris_probe",
                headers={
                    "X-Slow-Header-A": "keep-alive-drip",
                    "X-Slow-Header-B": "chunked-starvation-test",
                },
                timeout=1.0,
            )
            status: EventStatus = "ok"
        except Exception as exc:
            logger.warning(f"slowloris HTTP error: {exc}")
            status = "invalid"

        logger.debug(f"SLOWLORIS  dest={dest_str}  → status={status}")
        return _build_network_event(
            src_ip=attacker_ip,
            dest_ip_port=dest_str,
            attack_type="slowloris_attack",
            protocol="tcp",
            status=status,
            payload_details={
                "method": "GET",
                "attack_vector": "slow_headers",
                "simulated_connections": random.randint(20, 100),
                "keep_alive_interval_sec": 15,
                "description": "Slowloris header starvation holding HTTP socket descriptors open",
            },
            is_attack=True,
        )

    # ── Normal benign traffic ─────────────────────────────────────────────────

    async def generate_normal_auth(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """Send POST /login with valid credentials (status: 'ok')."""
        client = self._client_or_raise()
        src_ip = _corp_ip()
        username, password = random.choice(list(VALID_CREDENTIALS.items()))

        try:
            resp = await client.post(
                f"{target_url}/login",
                json={"username": username, "password": password},
            )
        except Exception as exc:
            logger.warning(f"normal_auth HTTP error: {exc}")
            resp = httpx.Response(503)

        return _build_auth_event(
            resp, src_ip, target_url,
            username, password, "normal_auth", is_attack=False,
        )

    async def generate_normal_api(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """Send GET /api/search with a benign query (status: 'ok')."""
        client = self._client_or_raise()
        src_ip = _corp_ip()
        q = random.choice(BENIGN_QUERIES)
        endpoint = f"/api/search?q={q}"

        try:
            resp = await client.get(f"{target_url}{endpoint}")
        except Exception as exc:
            logger.warning(f"normal_api HTTP error: {exc}")
            resp = httpx.Response(503)

        return _build_api_event(
            resp, src_ip, target_url,
            endpoint, "GET", "normal_api_call",
            None, None, is_attack=False,
        )

    async def generate_normal_network(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """Send normal benign network connection telemetry (status: 'ok')."""
        src_ip = _corp_ip()
        dest_str = _dest_from_url(target_url)
        return _build_network_event(
            src_ip=src_ip,
            dest_ip_port=dest_str,
            attack_type="benign_traffic",
            protocol="tcp",
            status="ok",
            payload_details={
                "traffic_type": "standard_http_handshake",
                "description": "Routine TCP connection established",
            },
            is_attack=False,
        )

    # ── Dispatcher ────────────────────────────────────────────────────────────

    async def generate_random_event(
        self,
        target_url: str = "http://localhost:8002",
        target_user: str = "admin",
        only_attacks: bool = False,
        selected_scenarios: Optional[List[str]] = None,
        attack_ratio: float = 0.3,
        **_,
    ) -> SecurityEvent:
        is_attack = only_attacks or (random.random() < attack_ratio)

        if is_attack:
            pool = selected_scenarios or [
                "auth_brute_force", "auth_jwt_tampering",
                "api_injection_probe", "api_rate_limit",
                "network_port_scan", "network_slowloris",
            ]
            scenario = random.choice(pool)
            return await self.trigger_named_attack(
                scenario, target_url=target_url, target_user=target_user
            )
        else:
            r = random.random()
            if r < 0.4:
                return await self.generate_normal_auth(target_url=target_url)
            elif r < 0.8:
                return await self.generate_normal_api(target_url=target_url)
            else:
                return await self.generate_normal_network(target_url=target_url)

    async def trigger_named_attack(
        self,
        scenario_name: str,
        target_url: str = "http://localhost:8002",
        target_user: str = "admin",
        **_,
    ) -> SecurityEvent:
        if scenario_name == "auth_brute_force":
            return await self.generate_auth_brute_force(target_url, target_user)
        elif scenario_name == "auth_jwt_tampering":
            return await self.generate_auth_jwt_tampering(target_url, target_user)
        elif scenario_name in ("api_injection_probe", "api_sql_injection"):
            return await self.generate_api_injection_probe(target_url)
        elif scenario_name == "api_rate_limit":
            return await self.generate_api_rate_limit(target_url)
        elif scenario_name == "network_port_scan":
            return await self.generate_network_port_scan(target_url)
        elif scenario_name == "network_slowloris":
            return await self.generate_network_slowloris(target_url)
        else:
            logger.warning(f"Unknown scenario '{scenario_name}', defaulting to brute_force.")
            return await self.generate_auth_brute_force(target_url, target_user)


