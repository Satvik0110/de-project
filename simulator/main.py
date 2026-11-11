"""Red team: attack simulator API (port 8001), driven by the console in frontend/.

The simulator only ACTS. The target web app and the network sensor log what they observe
and ship it to ingest, as defended systems do. The one thing the simulator reports is
ground truth: which campaign it ran, from which IPs, expecting which detections. That
goes to its own Kafka topic (security.sim.campaigns), which only the scoreboard reads,
so the detection path cannot see it.

Run:  uvicorn simulator.main:app --port 8001
"""
import asyncio
import json
import logging
import random
import uuid
from collections import Counter, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from confluent_kafka import Producer
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ingest.config import KAFKA_BOOTSTRAP
from .actors import Actor
from .scenarios import BY_ID, EMPLOYEES, SCENARIOS, Campaign, employee_action

TOPIC_CAMPAIGNS = "security.sim.campaigns"
CHAOS_URLS = ["http://127.0.10.1:8002/chaos", "http://127.0.0.1:8004/chaos"]
BACKGROUND_RATE = 5.0                       # employee actions per second
EMPLOYEE_HOSTS = [(f"127.0.1.{10 + i}", list(EMPLOYEES)[i % len(EMPLOYEES)]) for i in range(24)]

log = logging.getLogger("simulator")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Hub:
    def __init__(self):
        self.background = True
        self.chaos = False
        self.campaigns: deque = deque(maxlen=20)
        self.running: dict[str, dict] = {}                 # scenario id -> campaign
        self.stats = Counter()
        self.sockets: set[WebSocket] = set()
        self.next_ip = 1
        self.producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP, "acks": "all",
                                  "enable.idempotence": True})

    # -- output ------------------------------------------------------------------
    async def broadcast(self, msg: dict) -> None:
        for ws in list(self.sockets):
            try:
                await ws.send_json(msg)
            except Exception:
                self.sockets.discard(ws)

    def on_request(self, entry: dict) -> None:
        self.stats["requests_sent"] += 1
        self.stats[f"{entry['team']}_requests"] += 1
        self.stats[f"kind.{entry['kind']}"] += 1
        self.stats[f"outcome.{entry['outcome']}"] += 1
        asyncio.create_task(self.broadcast({"type": "log", "entry": entry}))

    def stats_view(self) -> dict:
        s = self.stats
        return {"requests_sent": s["requests_sent"], "attack_requests": s["attack_requests"],
                "normal_requests": s["normal_requests"],
                "by_kind": {k: s[f"kind.{k}"] for k in ("auth", "api", "network")},
                "outcomes": {k: s[f"outcome.{k}"] for k in ("success", "fail", "denied", "error")}}

    def state(self) -> dict:
        return {"background": self.background, "chaos": self.chaos,
                "scenarios": [{"id": s.id, "name": s.name, "tactic": s.tactic, "technique": s.technique,
                               "description": s.description, "expected_rules": list(s.expected)}
                              for s in SCENARIOS],
                "campaigns": list(self.campaigns), "stats": self.stats_view()}

    def publish(self, campaign: dict) -> None:
        self.producer.produce(TOPIC_CAMPAIGNS, key=campaign["campaign_id"], value=json.dumps(campaign))
        self.producer.poll(0)

    # -- campaigns ---------------------------------------------------------------
    async def launch(self, scenario_id: str) -> dict:
        sc = BY_ID[scenario_id]
        if sc.botnet:
            n = self.next_ip
            ips = [f"127.77.{n % 250}.{i + 1}" for i in range(sc.botnet)]
        else:
            ips = [f"127.66.{self.next_ip // 250}.{self.next_ip % 250 + 1}"]
        self.next_ip += 1
        campaign = {"campaign_id": str(uuid.uuid4()), "scenario": sc.id, "status": "running",
                    "started_at": now_iso(), "ended_at": None, "attacker_ips": ips,
                    "target_user": sc.target_user, "expected_rules": list(sc.expected), "requests": 0}
        self.running[sc.id] = campaign
        self.campaigns.appendleft(campaign)
        self.publish(campaign)
        await self.broadcast({"type": "campaign", "campaign": campaign})
        asyncio.create_task(self._run(sc, campaign))
        return campaign

    async def _run(self, sc, campaign: dict) -> None:
        actors = [Actor(ip, "attack", self.on_request, campaign) for ip in campaign["attacker_ips"]]
        try:
            await sc.run(Campaign(actors))
        except Exception:
            log.exception("campaign %s failed", sc.id)
        finally:
            for a in actors:
                await a.close()
            campaign.update(status="done", ended_at=now_iso(), requests=sum(a.requests for a in actors))
            self.running.pop(sc.id, None)
            self.publish(campaign)
            await self.broadcast({"type": "campaign", "campaign": campaign})

    # -- background ----------------------------------------------------------------
    async def background_loop(self) -> None:
        actors = {ip: Actor(ip, "normal", self.on_request) for ip, _ in EMPLOYEE_HOSTS}
        sessions: dict = {ip: {} for ip in actors}
        while True:
            if self.background:
                ip, user = random.choice(EMPLOYEE_HOSTS)
                asyncio.create_task(employee_action(actors[ip], user, sessions[ip]))
            await asyncio.sleep(random.expovariate(BACKGROUND_RATE))

    async def stats_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            await self.broadcast({"type": "stats", "stats": self.stats_view()})

    async def set_chaos(self, enabled: bool) -> None:
        async with httpx.AsyncClient(timeout=3) as c:
            results = await asyncio.gather(*(c.post(u, json={"enabled": enabled}) for u in CHAOS_URLS),
                                           return_exceptions=True)
        if any(isinstance(r, Exception) or r.status_code != 200 for r in results):
            raise HTTPException(502, "could not reach target/sensor to change network conditions")
        self.chaos = enabled


hub = Hub()


@asynccontextmanager
async def lifespan(app: FastAPI):
    tasks = [asyncio.create_task(hub.background_loop()), asyncio.create_task(hub.stats_loop())]
    yield
    for t in tasks:
        t.cancel()
    hub.producer.flush(5)


app = FastAPI(title="Attack simulator", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class Toggle(BaseModel):
    enabled: bool


class Launch(BaseModel):
    scenario: str


@app.get("/api/state")
def get_state():
    return hub.state()


@app.post("/api/background")
async def set_background(t: Toggle):
    hub.background = t.enabled
    await hub.broadcast({"type": "toggles", "background": hub.background, "chaos": hub.chaos})
    return hub.state()


@app.post("/api/chaos")
async def set_chaos(t: Toggle):
    await hub.set_chaos(t.enabled)
    await hub.broadcast({"type": "toggles", "background": hub.background, "chaos": hub.chaos})
    return hub.state()


@app.post("/api/attack")
async def attack(req: Launch):
    if req.scenario not in BY_ID:
        raise HTTPException(404, f"unknown scenario {req.scenario!r}")
    if req.scenario in hub.running:
        raise HTTPException(409, f"{req.scenario} is already running")
    return {"campaign_id": (await hub.launch(req.scenario))["campaign_id"]}


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    hub.sockets.add(websocket)
    await websocket.send_json({"type": "state", **hub.state()})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        hub.sockets.discard(websocket)
