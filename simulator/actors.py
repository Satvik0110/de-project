"""An actor is one machine on the simulated network: an employee or an attacker.

Each actor connects FROM its own address. Linux routes all of 127.0.0.0/8 to loopback,
so binding the client socket to e.g. 127.66.0.5 gives the target and sensor a real,
kernel-observed source IP, with no spoofed headers. The actor never reports events
itself; it only acts, and the defended systems log what they see.
"""
import asyncio
from datetime import datetime, timezone
from typing import Callable, Optional

import httpx

TARGET = "http://127.0.10.1:8002"
SERVER = "127.0.10.1"

Logger = Callable[[dict], None]


class Actor:
    def __init__(self, ip: str, team: str, log: Logger, campaign: Optional[dict] = None):
        self.ip, self.team, self._log, self.campaign = ip, team, log, campaign
        self.http = httpx.AsyncClient(base_url=TARGET, timeout=5.0,
                                      transport=httpx.AsyncHTTPTransport(local_address=ip))
        self.requests = 0

    async def close(self) -> None:
        await self.http.aclose()

    def _record(self, kind: str, action: str, result: str, outcome: str) -> None:
        self.requests += 1
        self._log({
            "at": datetime.now(timezone.utc).isoformat(), "team": self.team,
            "campaign_id": self.campaign["campaign_id"] if self.campaign else None,
            "scenario": self.campaign["scenario"] if self.campaign else None,
            "src_ip": self.ip, "kind": kind, "action": action, "result": result, "outcome": outcome,
        })

    async def _http(self, kind: str, action: str, method: str, url: str, **kw) -> Optional[httpx.Response]:
        try:
            r = await self.http.request(method, url, **kw)
        except httpx.HTTPError:
            self._record(kind, action, "error", "error")
            return None
        outcome = "success" if r.status_code < 400 else ("denied" if r.status_code in (403, 429) else "fail")
        self._record(kind, action, str(r.status_code), outcome)
        return r

    async def login(self, user: str, password: str) -> Optional[str]:
        r = await self._http("auth", f"POST /login user={user}", "POST", "/login",
                             json={"username": user, "password": password})
        return r.json()["token"] if r is not None and r.status_code == 200 else None

    async def search(self, q: str) -> None:
        await self._http("api", f"GET /api/search?q={q}", "GET", "/api/search", params={"q": q})

    async def export(self, token: Optional[str] = None) -> None:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        await self._http("api", "POST /api/export" + ("" if token else " (no token)"),
                         "POST", "/api/export", headers=headers)

    async def connect(self, host: str, port: int) -> str:
        """TCP connect + banner grab: 'open' if the service speaks, 'closed' if reset."""
        action = f"TCP {host}:{port}"
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, local_addr=(self.ip, 0)), 1.0)
        except (OSError, asyncio.TimeoutError):
            self._record("network", action, "closed", "denied")
            return "closed"
        try:
            state = "open" if await asyncio.wait_for(reader.read(64), 0.5) else "closed"
        except (OSError, asyncio.TimeoutError):
            state = "closed"
        writer.close()
        self._record("network", action, state, "success" if state == "open" else "denied")
        return state
