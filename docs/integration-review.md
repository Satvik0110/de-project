# Integration Review: Simulator + Pipeline

> **Historical record.** This review was written before the integration and guided it. Where it
> differs from the code, the README is current (notably: events are now logged by the defended
> systems, not the simulator — section 3 "considered and deferred" was implemented after all).

Branch: `integrate-simulator` (merge commit `ca0083a`). Written 2026-11-11 for a **2-day** deadline.
No code has been changed. This document is the basis for the Q&A that follows.

---

## 1. What Maulik built

Three pieces, each a separate process:

| Piece | Port | What it does |
|---|---|---|
| `target/` | 8002 | The **victim**: a FastAPI app with no protections. `POST /login` (7 real users, returns 200 or 401), `GET /api/search`, `POST /api/export` (always 200). |
| `simulator/` | 8001 | The **attacker**: sends *real* HTTP requests and TCP connections to the target, builds one `SecurityEvent` from each real response, streams events to the UI over WebSocket, and can forward them to our ingest API. |
| `frontend/` | 5173 | React/Vite **control panel** (FR4): start/pause, events per second, which attacks run continuously, one-click attack bursts, a live event feed and an event inspector. |

### Attacks simulated (6)

| Scenario | What actually happens | Realism |
|---|---|---|
| `auth_brute_force` | `POST /login` against one account with a 1,200-word generated wordlist; correct password used with probability 1/1000 | Good |
| `auth_password_spray` | Common passwords across 15 usernames, from 3 rotating IPs | Good |
| `api_injection_probe` | 22 real payloads: SQLi (4 kinds), OS command injection, path traversal, NoSQL, SSTI, XSS, LDAP, CRLF | **Very good**; the richest part |
| `api_rate_limit` | 5 concurrent `POST /api/export` calls | OK |
| `network_port_scan` | Real TCP connect to 20 well-known ports on the target host | Good |
| `network_connection_flood` | 8 concurrent TCP connections to the target port | OK |

Benign traffic: successful logins by alice/bob, normal search queries, and made-up "normal" network events.

### Verdict: is it too basic?
No. Real requests against a real victim (instead of fabricated JSON) and a broad set of injection payloads are good, defensible choices. The weak points are in **how events are labelled and attributed**, and those are what break integration and detection (section 2). The UI is polished.

---

## 2. Integration blockers (nothing works end to end until these are fixed)

Every event the simulator sends today would be **rejected**, at ingest or in the processor.

| # | Problem | Where it breaks | Fix on which side, and why |
|---|---|---|---|
| B1 | `status` is `ok` / `invalid`; the contract is `success` / `fail` / `denied` | Ingest returns 422 for every event | **Simulator.** The contract (Lab 3 section 4) is the shared agreement. `ok/invalid` also loses the fail-vs-denied distinction that `api_access_probing` relies on. Mapping: 200→success, 401→fail, 403/429/5xx/refused→denied. |
| B2 | Field is sent as `dest_ip:port`; the contract says `dest_ip_port` | 422 (unknown field) | **Simulator.** The colon was already discussed and settled in the README's open question. One contract, no aliases at ingest. |
| B3 | `dest_ip_port` holds a hostname (`localhost:8002`) | Processor sends **every** event to the DLQ (not a valid IP) | **Simulator.** The contract says ip:port, and resolving a name is the event producer's job. The processor rejecting non-IPs is correct; relaxing it would let `localhost` and `127.0.0.1` split one target into two entities. |
| B4 | Forwarding URL is `/api/v1/events`; ours is `/events`. Forwarding is **off** by default | Nothing reaches Kafka | **Simulator** config defaults. |
| B5 | The attacker IP is re-randomised **per event** from a pool of 6 | A 25-attempt brute force is spread over 6 IPs (about 4 each, below the threshold of 5), so it raises `distributed_brute_force` instead of `brute_force`. Port scans are diluted the same way. | **Simulator.** A real campaign keeps one source (one hydra/nmap run = one IP). Distributed attacks should be their own explicit scenario. See S1. |
| B6 | Rate-limit and connection-flood send 5–8 real requests but emit **1 event** | Volume rules undercount by 5–8×; `api_flood` (50) is barely reachable | **Simulator.** One event per real request or connection, the way real access logs work. |
| B7 | No rule exists for injection probes or connection floods | Two of the six attacks can never alert (the target always returns 200, so probing rules don't see them) | **Processor.** Detection belongs in the detector. See P1. |

---

## 3. Design issues worth fixing (beyond the blockers)

### Simulator side
- **S1. Attack "campaigns" with ground-truth labels.** Each burst should be a campaign with a `campaign_id`, one attacker IP, a scenario, and start/end times, carried in `raw_payload.sim = {campaign_id, scenario, malicious}`. Today `threat_flag`/`severity` sit loose in `raw_payload`. The labels **must never be read by the processor** (that would be the attacker grading its own homework), only by evaluation (section 5). This also fixes B5.
- **S2. Dispatch is fire-and-forget** (`asyncio.create_task` per event, no retry, unbounded). At high EPS that means unbounded tasks, lost events on a 503, and arbitrary reordering. Replace it with a bounded `asyncio.Queue` and worker(s) that retry with backoff on 503. That uses the backpressure ingest already signals; Lab 2's FR1 risk was "generator might drop events under heavy load".
- **S3. `inject_late_watermark` / `inject_duplicates` exist in config and UI but are not implemented.** Implementing them in the dispatcher is cheap, and it demos our dedup and lateness handling from the UI: toggle it on and see `duplicate` / `late` counters move on the dashboard.
- **S4. The brute-force success rate (1/1000) means the critical `brute_force_success` alert never shows in a demo.** Make success happen after N attempts, configurable per campaign.
- **S5. Benign traffic is too clean** (no benign failed logins), and the default mode is 100% attacks. Without realistic noise there is nothing to measure false positives against. Add about 3–5% benign failures and make mixed mode the demo default.
- **S6. Minor:** drop `ingest_time` from simulator events (ingest overwrites it anyway); send `user=null` instead of `"anonymous"` (it inflates `unique_users`); CORS `*` together with `allow_credentials=True` is rejected by browsers (harmless locally).

### Processor / Kafka side
- **P1. Two new rules.**
  - `injection_probe`: a stateless signature match on `raw_payload.endpoint`/query (SQLi, traversal, SSTI, etc.). It fires on the first hit and escalates on count. `raw_payload` is defined in Lab 3 as "unparsed extra fields", and normalising it is exactly the processor's cleaning step, so the contract stays v1.
  - `connection_flood`: network events per `(src_ip, dest_ip, dest_port)` at or above N per window. `port_scan` (distinct ports) and `host_sweep` (distinct hosts) cannot see many connections to the same port.
- **P2. Latency metrics:** we publish avg and max detection latency. Add **p50/p95/p99**, since averages hide tail behaviour, which is the metric that matters for an alerting system (Dean & Barroso, *The Tail at Scale*, CACM 2013). Also break latency down by stage: event→ingest, ingest→processor, processor→alert.
- **P3. MITRE ATT&CK tag on every rule** (cheap, professional, and gives a shared vocabulary in the dashboard and in LLM prompts):

  | Rule | ATT&CK |
  |---|---|
  | brute_force | T1110.001 Password Guessing |
  | password_spray | T1110.003 Password Spraying |
  | brute_force_success | T1110 + T1078 Valid Accounts |
  | distributed_brute_force | T1110 |
  | port_scan / host_sweep | T1046 Network Service Discovery |
  | injection_probe | T1190 Exploit Public-Facing Application |
  | api_flood / connection_flood | T1499 Endpoint Denial of Service |
  | api_access_probing | T1595 Active Scanning |

- **No change needed** to the core design: windows, watermark, dedup, early alerts, commit protocol and deterministic `alert_id`. These are the strongest part of the project.

### Architecture: considered and *deferred*
- **Who should emit the events?** Today the **attacker** reports what happened. In a real SIEM the **defended system** emits logs (the target app, plus a firewall or IDS for network events), and the attacker only attacks, with its identity in `X-Forwarded-For`. That is more realistic, but the target cannot see TCP connects to closed ports, so a "network sensor" would still be needed. **Deferred because of the 2-day limit**; worth mentioning as a known limitation and future work in the viva.
- **Real HTTP caps throughput.** Each event waits for a real request, so the simulator tops out in the low hundreds of events per second (UI slider max 150). That is fine for demos but cannot stress the processor. For benchmarks see section 5.3.

---

## 4. Proposed target architecture (2-day scope)

```
 Frontend (React)  ── control ─▶  Simulator ──HTTP/TCP──▶ Target (victim)
   ▲  ▲                              │ events (bounded queue, retry)
   │  │                              ▼
   │  │                        Ingest API ──▶ Kafka: security.events.raw
   │  │                                         │                │
   │  │                         ┌───────────────┘                └──────────────┐
   │  │                         ▼                                               ▼
   │  │                 Stream Processor                                 Lake Writer
   │  │           alerts / aggregates / metrics                    Parquet, year/month/day/hour
   │  │                         │  (Kafka topics)                     (+ sim labels kept)
   │  │                         ▼
   │  │                 Warehouse Writer ──▶ PostgreSQL ◀── LLM Summariser (async, off hot path)
   │  │                 upsert on alert_id    alerts, aggregates, metrics,
   │  │                                       incidents, campaigns
   │  └── live (WebSocket, pushed from Kafka) ───────────┐
   └───── history / scoreboard (SQL) ─────────── Dashboard API (FastAPI)
```

Key decisions:
1. **The lake writer is a separate consumer group, not part of the processor** (as in Lab 6–8). Kafka consumer groups give independent fan-out for free (Kreps, *The Log*), and disk I/O stays off the detection path.
2. **The warehouse writer is a separate consumer of the output topics** and does `INSERT … ON CONFLICT (alert_id) DO UPDATE`. That follows directly from the deterministic `alert_id` plus at-least-once delivery: replays become idempotent upserts. The processor keeps one job.
3. **Dashboard = a second view in the existing React app**, served by a small Dashboard API. Live alerts and metrics are **pushed** over WebSocket straight from Kafka, and history and scoreboards come from Postgres via SQL. This answers Lab 2's FR5 risk ("frequent auto polling slowing backend analytical queries"), and it puts *trigger attack → see alert* on one screen, which is the closed-loop gap from Lab 2 section 3. Grafana would be quicker to set up but cannot do the closed loop or the scoreboard nicely.
4. **The LLM runs asynchronously, outside the processor.** It summarises **incidents** (groups of alerts), not single alerts or events. That keeps cost and rate limits bounded and has zero effect on detection latency. It only receives alert metadata and sample events, never secrets (passwords are already masked).

---

## 5. Showcase / "novel" pieces: recommendation

Ranked by value for effort in 2 days.

### 5.1 LLM incident summaries (requested): **do it**
Lab 1 objective: *"explore AI-based techniques to assist in understanding and summarising detected security events."* Summaries are much better on an **incident** than on a single alert, which is why 5.2 is paired with this.

### 5.2 Attack-chain incidents (light correlation): **do it**
Group alerts from the same attacker IP into an **incident** while they keep arriving within, say, 10 minutes of each other (a session window; Akidau et al., *The Dataflow Model*, 2015, already cited in our reports). The incident keeps the ordered list of ATT&CK tactics. Severity goes up if the incident spans 2 or more tactics (for example Discovery → Initial Access → Credential Access). Add one **multi-stage scenario** to the simulator: port scan → injection probe → brute force → successful login, all from one IP. In the demo, one button produces a single incident with a timeline and an LLM-written narrative, instead of four unrelated alerts. It is cheap because it is SQL over the alerts table, not new streaming state.

### 5.3 Detection scoreboard against ground truth: **do it (most "novel")**
Because the simulator **knows** what it launched (S1 labels), the platform can **grade itself**:
- **Recall / detection rate** per scenario: was the campaign alerted with the expected rule?
- **Precision / false positives**: alerts on benign entities, using mixed traffic (S5).
- **Time-to-detect**: first alert `detected_at` minus the campaign's first `event_time`. Our early-firing design should show sub-second times here, against the window length plus lateness (70s) that a close-time-only design would need.

This is how intrusion-detection systems are evaluated in the literature (labelled traffic, precision/recall; e.g. CICIDS2017, Sharafaldin et al., 2018), and commercial SIEMs don't ship it built in. It turns Lab 2's claim of a "stream-first, lower detection latency" design into a **measured** result.

### 5.4 Processor performance benchmark: **do it, small**
A load tool that writes **directly to Kafka** (bypassing the HTTP simulator, which caps at about 150 events/s) at fixed rates (for example 1k → 5k → 10k → 20k events/s). Record processor events/s, consumer lag, and p95 detection latency to find the **maximum sustainable throughput**, the point where lag starts growing without bound. That is the standard way to benchmark stream processors (Karimov et al., *Benchmarking Distributed Stream Data Processing Systems*, ICDE 2018). Show the curve on the dashboard. Be honest that a single-threaded Python processor is the limit, and explain why (single instance needed for the global watermark and the per-user rule).

### 5.5 Adaptive baselines: **skip**
A learned per-entity baseline (EWMA / z-score) needs a long run of normal traffic to learn, is hard to validate in 2 days, and makes false-positive tuning risky. Mention it as future work. The scoreboard from 5.3 would be the way to compare it against static thresholds.

---

## 6. Two-day plan (cut line marked)

**Day 1: make it work and store it**
1. Simulator fixes B1–B6, S1 (campaigns and labels), S2 (queue and retry), S4, S5
2. Processor P1 (two rules) and P3 (ATT&CK tags); P2 latency percentiles in metrics
3. Lake writer (Parquet, Hive partitions; the design is already written in Lab 6–8)
4. Postgres plus warehouse writer (alerts, aggregates, metrics, campaigns)
5. End-to-end test: simulator → alerts in Postgres

**Day 2: show it**

6. Dashboard API and dashboard view: live alerts, pipeline metrics (throughput, lag, p50/p95 latency, dedup/late/DLQ counts), aggregates over time
7. Incidents (5.2) plus the multi-stage scenario
8. Detection scoreboard (5.3)
9. LLM incident summaries (5.1)

──── **cut line**: below this is only if time remains ────

10. Benchmark tool and throughput curve (5.4)
11. S3 duplicate/late injection toggles
12. Docker Compose for Postgres (or one-command startup)

---

## 7. Open questions for the Q&A

1. **Postgres**: install natively (apt), like Kafka, or run it in Docker?
2. **One UI or two**: add the dashboard as a tab in Maulik's React app (my recommendation), or keep a separate app?
3. **Contract**: OK to keep v1 and put the new data (`sim` labels, http endpoint) in `raw_payload`? Or bump to v2 with first-class fields? I recommend staying on v1, since a bump costs time and touches every component.
4. **Demo flow**: is there a fixed demo script (e.g. a 5-minute viva)? If so, the multi-stage scenario and scoreboard should be built around it.
5. **LLM**: which provider and key will you use? Is sending alert metadata to an external API acceptable to your instructor?
6. **Event emitter**: are you happy to defer the "victim emits logs" redesign (section 3) to future work?
