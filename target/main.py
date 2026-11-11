"""Target web application: the defended system the simulator attacks.

Deliberately unprotected (no WAF, lockout or rate limit) so attacks fully play out and
detection is entirely the SIEM's job. Like any real server it writes a security log:
every request becomes one event, built from what the SERVER observed (peer IP of the
TCP connection, the request line, the status code it returned) and shipped to ingest.

  POST /login        200 + token | 401
  GET  /api/search   200 (public; passes the query through unfiltered)
  POST /api/export   200 with a valid bearer token | 401

Run:  uvicorn target.main:app --host 127.0.10.1 --port 8002
"""
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from shipper import LogShipper, make_event

USERS = {
    # privileged accounts (attack targets)
    "admin": "Admin@1234", "root": "t00r", "sysadmin": "Sysadmin99", "deploy": "deploy123",
    # employees (background traffic)
    "alice": "alice2026", "bob": "bob_secure", "carol": "carol#77", "dave": "dave_pw1",
    "erin": "erin2026!", "frank": "frank_99", "grace": "grace@home", "heidi": "heidi123",
}
CONTROL_PATHS = {"/health", "/chaos"}       # operational endpoints, not part of the security log

shipper = LogShipper("target")
tokens: dict[str, str] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    await shipper.start()
    yield
    await shipper.stop()


app = FastAPI(title="Target web app", lifespan=lifespan)


def _status(code: int) -> str:
    if code < 400:
        return "success"
    return "denied" if code in (403, 429) else "fail"


@app.middleware("http")
async def access_log(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path not in CONTROL_PATHS:
        host, port = request.scope["server"]
        shipper.emit(make_event(
            source_type="auth" if path == "/login" else "api",
            src_ip=request.client.host,
            dest=f"{host}:{port}",
            status=_status(response.status_code),
            user=getattr(request.state, "user", None),
            raw={"method": request.method, "path": path, "query": request.url.query,
                 "http_status": response.status_code,
                 "user_agent": request.headers.get("user-agent")},
        ))
    return response


class Login(BaseModel):
    username: str
    password: str


@app.post("/login")
async def login(body: Login, request: Request):
    request.state.user = body.username
    if USERS.get(body.username) != body.password:
        raise HTTPException(401, "invalid credentials")
    token = secrets.token_hex(16)
    tokens[token] = body.username
    return {"token": token}


@app.get("/api/search")
async def search(q: str = ""):
    return {"query": q, "results": [f"item_{i}" for i in range(5)]}


@app.post("/api/export")
async def export(request: Request, authorization: str = Header(default="")):
    user = tokens.get(authorization.removeprefix("Bearer "))
    request.state.user = user
    if user is None:
        raise HTTPException(401, "authentication required")
    return {"status": "export_queued", "rows": 1000}


@app.get("/health")
async def health():
    return {"status": "ok", "shipper": dict(shipper.stats), "chaos": shipper.chaos}


class Toggle(BaseModel):
    enabled: bool


@app.post("/chaos")
async def chaos(t: Toggle):
    shipper.chaos = t.enabled
    return {"chaos": shipper.chaos}
