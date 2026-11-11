"""Attack scenarios and normal background activity.

Each scenario is one campaign by one attacker identity (a botnet for the distributed
one), shaped like the real tool would behave: a hydra run comes from one source, an
nmap scan probes one host's ports, a spray tries one password across many accounts.
The `expected` rules are the ground truth the scoreboard grades detection against;
the stream processor never sees them.
"""
import asyncio
import random
from dataclasses import dataclass
from typing import Awaitable, Callable

from .actors import SERVER, Actor

OPEN_SERVICE = 8080
SCAN_PORTS = [1433, 1521, 2049, 2222, 2375, 3306, 3389, 5000, 5601, 5900,
              6379, 8080, 8443, 8888, 9000, 9200, 11211, 27017, 50000, 61616]
WORKSTATIONS = [f"127.0.10.{i}" for i in range(2, 22)]
RDP = 3389

PRIVILEGED = ["admin", "root", "sysadmin", "deploy"]
EMPLOYEES = {"alice": "alice2026", "bob": "bob_secure", "carol": "carol#77", "dave": "dave_pw1",
             "erin": "erin2026!", "frank": "frank_99", "grace": "grace@home", "heidi": "heidi123"}
SPRAY_USERS = PRIVILEGED + list(EMPLOYEES) + ["guest", "test", "operator", "support"]
WORDLIST = [w + s for w in ("password", "admin", "welcome", "letmein", "dragon", "monkey",
                            "summer", "winter", "qwerty", "master", "shadow", "secret")
            for s in ("", "1", "123", "!", "2025", "2026", "@123")]
INJECTIONS = [
    "' OR '1'='1' --", "' UNION SELECT username, password FROM users --",
    "' AND 1=CONVERT(int, (SELECT @@version)) --", "1; WAITFOR DELAY '0:0:5' --",
    "id; cat /etc/passwd", "| whoami", "; powershell -c Get-Process", "& ping -n 3 127.0.0.1 &",
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fhosts",
    "admin[$ne]=x", '{"$where": "this.password.length > 0"}',
    "{{7*7}}", "${7*7}", "<script>alert('XSS')</script>", '"><img src=x onerror=alert(1)>',
    "*)(uid=*))(|(uid=*", "%0d%0aSet-Cookie:malicious=true",
]
BENIGN_QUERIES = ["monthly report", "user list", "inventory", "orders 2026", "dashboard stats",
                  "product catalog", "invoice 1043", "team calendar"]


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    tactic: str
    technique: str
    description: str
    expected: tuple[str, ...]
    run: Callable[["Campaign"], Awaitable[None]]
    botnet: int = 0                         # >0: this many source IPs instead of one
    target_user: str | None = None


class Campaign:
    """What a running scenario gets: its actors and a pace helper."""
    def __init__(self, actors: list[Actor]):
        self.actors = actors
        self.attacker = actors[0]

    @staticmethod
    async def pace(seconds: float = 0.05) -> None:
        await asyncio.sleep(seconds)


async def _scan(c: Campaign, ports=SCAN_PORTS) -> None:
    for port in ports:
        await c.attacker.connect(SERVER, port)
        await c.pace(0.05)


async def _sweep(c: Campaign) -> None:
    for host in WORKSTATIONS:
        await c.attacker.connect(host, RDP)
        await c.pace(0.05)


async def _inject(c: Campaign, payloads=INJECTIONS) -> None:
    for p in payloads:
        await c.attacker.search(p)
        await c.pace(0.1)


async def _brute(c: Campaign, user="admin", attempts=25) -> None:
    for pw in random.sample(WORDLIST, attempts):
        await c.attacker.login(user, pw)
        await c.pace(0.1)


async def _spray(c: Campaign) -> None:
    for user in SPRAY_USERS:
        await c.attacker.login(user, "Welcome2026!")
        await c.pace(0.15)


async def _distributed(c: Campaign) -> None:
    for _ in range(2):                         # each bot only tries twice: below brute_force
        for bot in c.actors:
            await bot.login("sysadmin", random.choice(WORDLIST))
            await c.pace(0.05)


async def _burst(n: int, concurrency: int, make) -> None:
    for i in range(0, n, concurrency):
        await asyncio.gather(*(make() for _ in range(min(concurrency, n - i))))


async def _api_flood(c: Campaign) -> None:
    await _burst(120, 10, lambda: c.attacker.search("item"))


async def _conn_flood(c: Campaign) -> None:
    await _burst(80, 10, lambda: c.attacker.connect(SERVER, OPEN_SERVICE))


async def _kill_chain(c: Campaign) -> None:
    """Recon -> exploit attempts -> credential attack -> account takeover -> data theft."""
    a = c.attacker
    await _scan(c)                                         # Discovery
    await c.pace(3)
    await _inject(c, INJECTIONS[:6])                       # Initial Access attempts
    await c.pace(3)
    for _ in range(12):                                    # Reconnaissance of protected API
        await a.export()
        await c.pace(0.1)
    await c.pace(3)
    await _brute(c, "admin", 8)                            # Credential Access
    token = await a.login("admin", "Admin@1234")           # Valid Accounts
    for _ in range(5):                                     # Exfiltration with the stolen session
        await a.export(token)
        await c.pace(0.3)


SCENARIOS = [
    Scenario("port_scan", "Port Scan", "Discovery", "T1046",
             "One attacker probes 20 service ports on the server.", ("port_scan",), _scan),
    Scenario("host_sweep", "Host Sweep", "Discovery", "T1046",
             "One attacker checks RDP on 20 workstations.", ("host_sweep",), _sweep),
    Scenario("injection_probe", "Injection Probes", "Initial Access", "T1190",
             "SQLi, command, traversal, NoSQL, template, XSS, LDAP and CRLF payloads against the search API.",
             ("injection_probe",), _inject),
    Scenario("brute_force", "Brute Force", "Credential Access", "T1110.001",
             "25 dictionary passwords against the admin account.", ("brute_force",), _brute),
    Scenario("password_spray", "Password Spray", "Credential Access", "T1110.003",
             "One common password tried across 16 accounts.", ("password_spray",), _spray),
    Scenario("distributed_brute_force", "Distributed Brute Force", "Credential Access", "T1110",
             "A 12-host botnet guesses one account, 2 tries per host to stay under per-IP limits.",
             ("distributed_brute_force",), _distributed, botnet=12, target_user="sysadmin"),
    Scenario("api_flood", "API Flood", "Impact", "T1499",
             "120 concurrent search requests from one source.", ("api_flood",), _api_flood),
    Scenario("connection_flood", "Connection Flood", "Impact", "T1499",
             "80 concurrent TCP connections to one service.", ("connection_flood",), _conn_flood),
    Scenario("kill_chain", "Multi-Stage Intrusion", "Discovery → Exfiltration", "T1046 → T1078",
             "Port scan, injection probes, API probing, brute force, then login with the cracked "
             "password and export data — all from one attacker.",
             ("port_scan", "injection_probe", "api_access_probing", "brute_force", "brute_force_success"),
             _kill_chain),
]
BY_ID = {s.id: s for s in SCENARIOS}


async def employee_action(actor: Actor, user: str, session: dict) -> None:
    """One step of normal activity. ~4% of logins are typos, as with real users."""
    r = random.random()
    if r < 0.2 or user not in session:
        pw = EMPLOYEES[user] if random.random() > 0.04 else EMPLOYEES[user][:-1]
        token = await actor.login(user, pw)
        if token:
            session[user] = token
    elif r < 0.6:
        await actor.search(random.choice(BENIGN_QUERIES))
    elif r < 0.75:
        await actor.export(session[user])
    else:
        await actor.connect(SERVER, random.choice([3306, 8080]))
