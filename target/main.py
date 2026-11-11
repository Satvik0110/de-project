"""
Target Web Application — purposefully simple victim server.
Role: Receive HTTP requests from the attack simulator and return honest HTTP responses.

Rules:
  - No built-in security guard, no WAF, no lockout, no rate limiting.
  - Returns only 2 outcomes: 200 OK or 401 Unauthorized for bad logins. No 403 or 429.
  - Pure JSON API.

Endpoints:
  POST /login              → 200 (credentials match) or 401 (credentials mismatch)
  GET  /api/search?q=...   → 200 (all queries processed without blocking)
  POST /api/export         → 200 (all requests processed without rate limiting)
  GET  /target/health      → 200 (system health and registered users)

Port: 8002
"""

import time
import logging
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("target")

# ── User database ─────────────────────────────────────────────────────────────
USERS: dict[str, str] = {
    "admin":         "Admin@1234",
    "root":          "t00r",
    "administrator": "P@ssw0rd!",
    "sysadmin":      "Sysadmin99",
    "deploy":        "deploy123",
    "alice":         "alice2026",
    "bob":           "bob_secure",
}

# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Attack Target Web Application",
    version="1.0.0",
    description="Target victim web app without security guards or rate limiters.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request models ────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class ExportRequest(BaseModel):
    format: Optional[str] = "csv"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/target/health")
def health():
    """Health check — shows registered users."""
    return {
        "status": "ok",
        "service": "Attack Target",
        "registered_users": list(USERS.keys()),
    }


@app.post("/login")
async def login(body: LoginRequest):
    """
    Authentication endpoint.
    - Returns 200 OK when username AND password match.
    - Returns 401 Unauthorized for wrong password or unknown username.
    - No lockout or banning.
    """
    correct_password = USERS.get(body.username)

    if correct_password is not None and correct_password == body.password:
        token = f"tok_{body.username}_{int(time.time())}"
        logger.info(f"LOGIN SUCCESS  user={body.username!r}")
        return {
            "status": "authenticated",
            "token": token,
            "username": body.username,
        }

    logger.info(
        f"LOGIN FAIL     user={body.username!r}  "
        f"pwd_tried={body.password[:3]}*** "
        f"({'unknown user' if correct_password is None else 'wrong password'})"
    )
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/search")
async def search(q: str = ""):
    """
    Search endpoint — processes all queries without security filtering.
    Always returns 200 OK.
    """
    logger.info(f"SEARCH QUERY   q={q[:80]!r}")
    return {
        "results": [f"item_{i}" for i in range(1, 6)],
        "query": q,
        "count": 5,
    }


@app.post("/api/export")
async def export(body: ExportRequest):
    """
    Export endpoint — processes all requests without rate limiting.
    Always returns 200 OK.
    """
    logger.info(f"EXPORT PROCESSED  fmt={body.format}")
    return {
        "status": "export_queued",
        "format": body.format,
        "estimated_rows": 1000,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("target.main:app", host="0.0.0.0", port=8002, reload=True)

