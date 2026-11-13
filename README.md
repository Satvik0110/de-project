# Real-Time Cybersecurity Event Analytics Platform

Group 4 (B23EE1094, B23ES1032, B23EE1041)

A stream-first SIEM. A red-team simulator runs real attacks against a lab network. The
defended systems log what they observe. A stream processor detects attacks within tens of
milliseconds of ingest. Everything is stored in a Parquet lake and a PostgreSQL warehouse,
and a SOC dashboard shows detections, multi-stage incidents with AI summaries, pipeline
health, and a scoreboard that grades detection against the simulator's ground truth.

```
 RED TEAM                     DEFENDED NETWORK (127.0.10.x)                BLUE TEAM
 ┌──────────────┐  HTTP   ┌───────────────────┐
 │ Simulator    │────────▶│ Target web app    │──┐ access log
 │ :8001        │  TCP    ├───────────────────┤  │ (log shipper:
 │ attackers    │────────▶│ Network sensor    │──┤  queue + retry)
 │ 127.66.x.x   │         └───────────────────┘  ▼
 │ employees    │                        ┌──────────────┐   security.events.raw   ┌──────────────────┐
 │ 127.0.1.x    │                        │ Ingest API   │────────────────────────▶│ Stream processor │
 └──────┬───────┘                        │ :8000        │      (Kafka, 3 parts)   │ windows, dedup,  │
        │ ground truth                   └──────────────┘            │            │ 10 rules, ATT&CK │
        │ security.sim.campaigns                                     ▼            └────────┬─────────┘
        │                                                     ┌─────────────┐   alerts, aggregates,
        │                                                     │ Lake writer │   pipeline.metrics
        │                                                     │ Parquet     │            │
        │                                                     └─────────────┘            ▼
        │                                                                     ┌────────────────────┐
        └────────────────────────────────────────────────────────────────────▶│ Warehouse writer   │
                                                                              │ PostgreSQL         │
 ┌──────────────┐                     ┌────────────────────────────┐          │ + incident chains  │
 │ Red console  │                     │ Dashboard API :8003        │◀─────────┴────────────────────┘
 │ :5173        │                     │ live: WebSocket from Kafka │──▶ SOC dashboard :5174
 └──────────────┘                     │ history: SQL; LLM summaries│
                                      └────────────────────────────┘
```

---

## Components

| Path | What it is |
|---|---|
| `simulator/` | **Red team.** 9 attack scenarios plus normal employee traffic. It only *acts*: every actor connects from its own real source IP (Linux routes all of `127.0.0.0/8` to loopback). It publishes ground truth (campaign, attacker IPs, expected rules) to `security.sim.campaigns`. |
| `frontend/` | Red-team console: launch attacks, toggle background traffic and "unreliable network", live attack log. |
| `target/` | The **defended web app** (`/login`, `/api/search`, `/api/export`). Deliberately unprotected. Logs every request as a security event, using the peer IP and status code that the *server* observed. |
| `sensor/` | **Network sensor.** Listens on the server's service ports and 20 workstations, and logs every TCP connection (open port = `success`, closed = reset and `denied`). It sees the scans the web app never would. |
| `shipper/` | Log shipper shared by target and sensor (the role Filebeat/Fluent Bit play in production): bounded queue, retry with backoff on ingest backpressure. In chaos mode it duplicates and delays events on purpose. |
| `ingest/` | Ingest API: validates against the frozen contract (`contracts/event.schema.json`), stamps `ingest_time`, produces to Kafka keyed by `src_ip`, sends invalid payloads to the DLQ. |
| `processor/` | Stream processor: event-time sliding windows, watermark, dedup, 10 detection rules tagged with MITRE ATT&CK, early alerting, at-least-once with restart recovery. |
| `lake/` | Lake writer: raw events → Snappy Parquet, Hive partitions `year=/month=/day=/hour=`. `reader.py` reads it back deduplicated; `compact.py` merges each finished hour into one file. |
| `warehouse/` | Schema and analytical views, plus a writer that upserts alerts, aggregates, metrics and campaigns into PostgreSQL and chains alerts into incidents. |
| `dashboard/` | Dashboard API (live WebSocket, SQL history, scoreboard, raw-event provenance from the lake, LLM summariser) and the SOC dashboard UI (`dashboard/ui`). |
| `docker-compose.yml` | Kafka (KRaft) + PostgreSQL in Docker, for machines without the native Linux setup. |
| `tests/` | Unit tests and three end-to-end suites (see [Testing](#testing)). |
| `tools/mock_traffic.py` | Synthetic events posted straight to ingest. Used by the processor end-to-end test. |

### Kafka topics

| Topic | Partitions | Producer → consumers |
|---|---|---|
| `security.events.raw` | 3, key `src_ip` | ingest → processor, lake writer |
| `security.events.dlq` | 1 | ingest, processor (rejects, with reason) |
| `security.alerts` | 1, key entity | processor → warehouse writer, dashboard |
| `security.aggregates` | 1 | processor → warehouse writer |
| `security.pipeline.metrics` | 1 | processor → warehouse writer, dashboard |
| `security.sim.campaigns` | 1 | simulator → warehouse writer (scoreboard only) |

Each downstream service is its own consumer group, so the lake, warehouse and dashboard read
the same stream independently and none of them slows detection.

---

## Setup (one time)

Requires Linux, Java 17+, Python 3.10+, Node 18+ and PostgreSQL 16 (native, `apt install postgresql`).

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
./infra/setup-kafka.sh          # downloads Kafka 4.x (KRaft, no ZooKeeper), formats storage
./infra/setup-postgres.sh       # asks for sudo once: creates role/db "secops", applies the schema
npm install --prefix frontend
npm install --prefix dashboard/ui
cp .env.example .env            # optional: LLM key for AI incident summaries
```

### Alternative: Kafka and PostgreSQL in Docker (Windows, macOS, or no sudo)

`docker-compose.yml` runs the same broker (KRaft, same six topics) and the same warehouse
(role/db/password `secops`, `warehouse/schema.sql` applied), so every service runs unchanged.

```bash
docker compose up -d                  # Kafka on :9092, PostgreSQL on :5432
PG_PORT=5433 docker compose up -d     # if a native PostgreSQL already uses 5432; then set
                                      # WAREHOUSE_DSN=postgresql://secops:secops@localhost:5433/secops
```

On Windows, start each service with the commands from `scripts/start.sh`, plus one flag for
the dashboard: async psycopg needs the selector event loop.

```bash
uvicorn dashboard.api:app --port 8003 --loop asyncio:SelectorEventLoop
```

The simulator, target and sensor bind `127.x` source addresses, which is Linux-specific (see
the end of this file). `tools/mock_traffic.py` exercises everything else on any OS.

## Running

```bash
./scripts/start.sh      # Kafka, topics, all 8 services and both UIs, in the background
./scripts/stop.sh       # stop everything (--keep-kafka to leave the broker up)
./scripts/reset.sh      # clean slate before a demo: empty topics, lake and warehouse (Kafka must be up, services stopped)
```

- Red team console: <http://localhost:5173>
- SOC dashboard: <http://localhost:5174>
- Logs: `logs/<service>.log`

Without an LLM key, incident summaries come from a deterministic template, so the demo
never depends on an external API.

### Demo script (about 5 minutes)

1. Put both screens side by side. Background traffic is on: the dashboard shows throughput and **no alerts**, because normal behaviour doesn't fire anything.
2. **Brute Force.** An alert appears within about 100 ms of the first event over the threshold, tagged T1110.001. It escalates to critical at 3× the threshold.
3. **Port Scan**, then **Host Sweep.** The sensor sees connections the web app never would. One is vertical (many ports on one host), the other horizontal (one port on many hosts).
4. **Multi-Stage Intrusion.** Five alerts from one IP become **one critical incident**: Discovery → Initial Access → Reconnaissance → Credential Access. The summary notes the successful login and recommends actions.
5. Turn on **Unreliable network.** The *duplicates dropped* and *late dropped* tiles start counting, and alert counts stay correct: that's dedup and the watermark at work.
6. **Scoreboard:** recall, precision and time-to-detect for every campaign, graded against the simulator's ground truth.

---

## Detection (stream processor)

Follows Lab 3 section 3: parse and validate → event-time windows → watermark → dedup → rules.

- **Windows.** Sliding, 60 s long, sliding every 10 s. Stored as 10 s *panes*: each event lands in one pane, and a window is 6 consecutive panes, so no event is copied six times.
- **Watermark.** Newest `event_time` minus 10 s. A window closes when the watermark passes its end. Events for already-closed windows are dropped and counted as *late*. If input goes idle, the watermark follows the wall clock. Events more than 60 s in the future go to the DLQ, because a broken clock would otherwise make every honest event late.
- **Dedup.** `event_id`s are kept only for open windows, so memory stays bounded by the window length.
- **Early alerts.** Every rule measures something that only grows, so an alert fires the moment a threshold is crossed (`early`). It is re-sent as `escalated` at 3× the threshold and as `final` when the window closes, always under the same deterministic `alert_id`, so downstream writes are upserts. Overlapping windows are suppressed, so one attack gives one alert.
- **Delivery.** At-least-once. Offsets are committed only up to the oldest event in an open window, and only after Kafka has acknowledged all outputs. After a crash, the processor rebuilds open windows without re-emitting closed ones.
- **Single instance.** The global watermark and the per-user rule need every partition.

| Rule | Fires when, within one 60 s window | Key | ATT&CK | Severity |
|---|---|---|---|---|
| `brute_force` | ≥ 5 failed logins | src_ip + user | T1110.001 · Credential Access | high |
| `password_spray` | failures on ≥ 5 distinct accounts | src_ip | T1110.003 · Credential Access | high |
| `brute_force_success` | ≥ 5 failures, then a success | src_ip + user | T1078 · Initial Access | critical |
| `distributed_brute_force` | one account failing from ≥ 5 IPs | user | T1110 · Credential Access | high |
| `port_scan` | ≥ 10 distinct ports on one host | src_ip + dest_ip | T1046 · Discovery | medium |
| `host_sweep` | ≥ 10 distinct hosts | src_ip | T1046 · Discovery | medium |
| `connection_flood` | ≥ 30 connections to one service | src_ip + dest | T1499 · Impact | medium |
| `injection_probe` | any request matching an injection signature (SQLi, command, traversal, NoSQL, template, XSS, LDAP, CRLF) | src_ip | T1190 · Initial Access | medium |
| `api_flood` | ≥ 50 API requests | src_ip | T1499 · Impact | medium |
| `api_access_probing` | ≥ 10 denied or failed API calls | src_ip | T1595 · Reconnaissance | medium |

Thresholds can be overridden with `RULE_<NAME>_THRESHOLD`. `injection_probe` matches the decoded
request line, which the web server logs in `raw_payload`. The contract stays at v1.

**Metrics** (every 5 s, to `security.pipeline.metrics`): events/s, consumer lag, watermark
delay, detection latency p50/p95/p99 over the last 500 alerts, per-stage latency (ingest =
event→ingest, processing = ingest→processor), and counters (accepted, duplicate, late,
invalid, alerts by rule). Tail percentiles, not averages, are what matter for alerting.

## Storage

- **Lake.** Micro-batches (5,000 events or 30 s) of Snappy Parquet in `data_lake/year=/month=/day=/hour=/`, partitioned by `event_time`, so a late event still lands in its true hour. Each row keeps its Kafka partition and offset for provenance. Files are written to a temporary name and renamed into place, so readers never see a half-written file. Offsets are committed after the write, so a crash can store a duplicate and readers dedup on `event_id`.
  - **Reading.** `lake/reader.py` opens only the hour folders a time range touches and drops duplicate `event_id`s, so callers never see a replayed event: `python -m lake.reader --minutes 60 --src-ip 127.66.0.5`. DuckDB or pandas also work directly (`pyarrow.dataset`, hive partitioning).
  - **Compaction.** A 30 s flush leaves ~120 small files per busy hour, and every file costs an open and a footer read on each scan. `python -m lake.compact` merges each hour that ended over 15 min ago into one file sorted by `event_time`, with duplicates removed. It is safe while the writer runs: it deletes only the files it read, so a late event written meanwhile is picked up next time.
  - **Quarantine.** A record that cannot be parsed is kept, byte for byte, in `data_lake/_quarantine/<date>.jsonl` with its Kafka coordinates and the error. Nothing in the raw topic is silently lost.
- **Warehouse** (`warehouse/schema.sql`, applied by the writer at every start, idempotent):
  - `alerts`: upsert on `alert_id`
  - `incidents`
  - `aggregates`: per tumbling window and source type
  - `pipeline_metrics`
  - `campaigns`: ground truth, read only by the scoreboard
  - `warehouse_rejects`: messages that could not be stored (bad JSON, missing field, a value Postgres rejects), with Kafka coordinates. Each message is written in its own savepoint, so one bad message no longer crashes the writer on every restart, and the rest of its batch still commits.
  - Views (always current, nothing extra to maintain): `hourly_ip_stats` (per attacker IP per hour), `attack_type_breakdown` (per rule: volume, attackers, p50/p95 latency), `threat_actors` (per attacker across incidents: worst severity, multi-stage, compromised account).
- **Dashboard API, storage endpoints.** `/api/threat-actors`, `/api/attack-types` and `/api/ip-stats` serve the views. `/api/alerts/{id}/events` returns an alert's raw events from the lake, which makes the provenance from Lab 6–8 a single click. `/api/health` reports warehouse and lake status. SQL runs on a connection pool (`psycopg_pool`) instead of opening a connection per query.
- **Incidents.** Alerts from the same attacker are chained while they arrive less than 10 minutes apart (a session window). Two or more ATT&CK tactics make it **multi-stage** and raise it one severity level.
- **Summaries.** The summariser runs inside the dashboard service, off the detection path. It writes one summary per incident, only after the incident has been quiet for 8 s, and again only when the incident's content changes. It uses any OpenAI-compatible endpoint (Groq, Gemini), sends only alert metadata, and falls back to a template whenever the LLM is unavailable.

## Detection scoreboard

The simulator knows what it launched, so the platform grades itself:
- **Recall:** expected rules detected for each campaign.
- **Precision:** alerts attributable to a campaign. Anything else came from benign traffic and counts as a false positive.
- **Time-to-detect:** first matching alert minus campaign start.

The ground truth travels on its own topic that the processor never reads, so detection cannot "see the answers".

---

## Testing

```bash
python -m pytest tests/test_processor.py -v   # 46 unit tests, no Kafka needed
python -m pytest tests/test_lake.py -v        # lake writer, reader, compaction; no Kafka needed
python -m pytest tests/test_warehouse.py tests/test_dashboard.py -v
                                              # writer, incidents, rejects, views, API endpoints;
                                              # PostgreSQL needed (own throwaway schema), no Kafka
python -m tests.smoke_test                    # ingest: validation, DLQ, keying (broker + API up)
python -m tests.e2e_processor                 # processor: rules, dedup, late, DLQ, restart (broker + API up)
python -m tests.e2e_platform                  # whole platform, run like the demo (scripts/start.sh up)
```

Last full run: every one of the 9 scenarios raised exactly its expected rules, with no alert
on employee traffic. Detection latency was p50 41 ms and max 116 ms. Scoreboard recall and
precision were both 100%, with a median time-to-detect of about 0.6 s from campaign launch
(that includes the attack itself reaching the threshold).

## Design decisions

- **Defended systems write the log, not the attacker.** That's how a real SIEM is fed, and the attacker can't misreport its IP or outcomes. Source IPs come from the kernel (bound loopback addresses), not from spoofable headers.
- **Contract v1 is frozen.** `ingest_time` is stamped by the server. `event_time` must carry a UTC offset. Unknown fields are rejected at the door, and invalid payloads go to the DLQ rather than being dropped.
- **`acks=all` plus idempotent producers** everywhere, and dedup on `event_id` in the processor, because at-least-once delivery means duplicates.
- **One consumer group per downstream concern** (lake, warehouse, dashboard), so storage I/O never sits on the detection path.
- **Live data pushed, history pulled.** The dashboard gets alerts and metrics over a WebSocket fed from Kafka. Only history queries hit Postgres, which addresses the FR5 polling risk from Lab 2.

**Limitations and future work:**
- A single processor instance. A keyed shuffle would allow scaling out.
- Static thresholds. Adaptive per-entity baselines could be graded with the same scoreboard.
- The sensor terminates connections itself. It is not a passive packet tap.
- MinIO / object storage for the lake is not implemented.
- `pipeline_metrics` grows by one row every 5 s (about 17k a day) and has no retention job yet.
- Lake compaction runs on demand (`python -m lake.compact`), not on a schedule.

`docs/integration-review.md` has the review that guided the integration.

## Things that will trip you up

- **`auto.offset.reset` is per partition.** It only applies where a group has no committed offset.
- **`confluent_kafka.Consumer` is not thread-safe.** Keep each consumer on one thread. The dashboard runs its consumer in a dedicated thread.
- **Never re-run `kafka-storage.sh format`.** It wipes the cluster. `setup-kafka.sh` refuses to.
- **Topic auto-creation is off.** `scripts/start.sh` runs `infra/create-topics.sh`, which is idempotent.
- **The topic-name warning** about periods and underscores is harmless.
- **`127.x` source binding is Linux-specific.** On macOS each loopback alias would need `ifconfig lo0 alias`.
