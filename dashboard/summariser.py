"""Incident summaries: an LLM narrative, with a deterministic template as fallback.

Runs off the detection path, inside the dashboard service: detection latency never
waits on a model. It summarises INCIDENTS (not single alerts or events), only once an
incident has been quiet for QUIET_S, and again only if its content changes, so a free
tier's rate limits are plenty. Only alert metadata is sent; no raw events or secrets.

Any OpenAI-compatible endpoint works (Groq, Gemini's OpenAI endpoint, ...):
  LLM_BASE_URL, LLM_API_KEY, LLM_MODEL   (see .env.example). No key -> template only.
"""
import asyncio
import json
import logging
import os

import httpx
import psycopg
from psycopg.rows import dict_row

DSN = os.getenv("WAREHOUSE_DSN", "postgresql://secops:secops@localhost:5432/secops")
BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
API_KEY = os.getenv("LLM_API_KEY", "")
MODEL = os.getenv("LLM_MODEL", "")
QUIET_S, POLL_S = 8, 5

SYSTEM = ("You are a SOC analyst writing for an incident queue. In 3-4 plain sentences (no markdown, "
          "no headings): say what the attacker did in order, their likely goal, whether anything "
          "succeeded (a successful login means a compromised account), and the two most important "
          "response actions. Use only the facts given.")

log = logging.getLogger("summariser")


def template(inc: dict, alerts: list[dict]) -> str:
    who = inc["entity"].removeprefix("user:")
    target = "account " + who if inc["entity"].startswith("user:") else who
    stages = " → ".join(inc["tactics"]) or "unknown"
    mins = max(1, round((inc["last_seen"] - inc["first_seen"]).total_seconds() / 60))
    text = (f"{len(alerts)} alert(s) for {target} over ~{mins} min, stages: {stages}. "
            f"Rules: {', '.join(inc['rules'])}. Severity {inc['severity']}.")
    if "brute_force_success" in inc["rules"]:
        users = {a["username"] for a in alerts if a["rule_name"] == "brute_force_success"}
        text += f" A login succeeded after repeated failures: treat {', '.join(sorted(users))} as compromised."
    actions = ["reset the affected credentials and revoke sessions"] if "brute_force_success" in inc["rules"] else []
    if not inc["entity"].startswith("user:"):
        actions.insert(0, f"block {who} at the perimeter")
    else:
        actions.insert(0, f"enable MFA / lockout for {who}")
    return text + " Recommended: " + "; ".join(actions) + "."


async def llm(client: httpx.AsyncClient, inc: dict, alerts: list[dict]) -> str:
    facts = {
        "attacker": inc["entity"], "severity": inc["severity"], "stages": inc["tactics"],
        "alerts": [{"rule": a["rule_name"], "technique": a["technique"], "tactic": a["tactic"],
                    "count": a["count"], "user": a["username"], "target": str(a["dest_ip"]) if a["dest_ip"] else None,
                    "from": a["first_event_time"].isoformat(), "to": a["last_event_time"].isoformat()}
                   for a in alerts],
    }
    r = await client.post(f"{BASE_URL}/chat/completions", headers={"Authorization": f"Bearer {API_KEY}"},
                          json={"model": MODEL, "temperature": 0.2, "max_tokens": 300,
                                "messages": [{"role": "system", "content": SYSTEM},
                                             {"role": "user", "content": json.dumps(facts)}]})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


async def run() -> None:
    use_llm = bool(API_KEY and MODEL)
    log.info("incident summaries via %s", f"LLM {MODEL} @ {BASE_URL}" if use_llm else "template (no LLM_API_KEY/LLM_MODEL)")
    async with httpx.AsyncClient(timeout=20) as client:
        while True:
            try:
                async with await psycopg.AsyncConnection.connect(DSN, autocommit=True, row_factory=dict_row) as conn:
                    while True:
                        await summarise_pending(conn, client, use_llm)
                        await asyncio.sleep(POLL_S)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("summariser: %s; retrying", exc)
                await asyncio.sleep(POLL_S)


async def summarise_pending(conn, client, use_llm: bool) -> None:
    cur = await conn.execute(
        """SELECT * FROM incidents
           WHERE (summarised_at IS NULL OR updated_at > summarised_at)
             AND updated_at < now() - make_interval(secs => %s)
           ORDER BY updated_at LIMIT 3""", (QUIET_S,))
    for inc in await cur.fetchall():
        alerts = await (await conn.execute(
            "SELECT * FROM alerts WHERE incident_id = %s ORDER BY first_event_time",
            (inc["incident_id"],))).fetchall()
        text, source = template(inc, alerts), "template"
        if use_llm:
            try:
                text, source = await llm(client, inc, alerts), "llm"
            except Exception as exc:          # rate limit, network, bad key: never break the demo
                log.warning("LLM failed for %s (%s); using template", inc["incident_id"], exc)
        await conn.execute("UPDATE incidents SET summary = %s, summary_source = %s, summarised_at = now() "
                           "WHERE incident_id = %s", (text, source, inc["incident_id"]))
