# Real-Time Cybersecurity Event Analytics Platform — Ingestion + Stream Processing

Group 4 (B23EE1094, B23ES1032, B23EE1041)

This repo contains the **ingestion layer** (HTTP event API + Kafka) and the **stream
processor** (FR2): event-time sliding windows, watermark, dedup and detection rules.

```
Attack Simulator  --HTTP-->  Ingest API  --produce-->  Kafka  --consume-->  Stream Processor  -->  security.alerts
 (FR1; mock for now)          [ingest/]              [infra/]               [processor/]          security.aggregates
                                                                                                  security.pipeline.metrics
```

The Parquet data lake and PostgreSQL warehouse (FR3) are not built yet. Until then the
processor publishes its outputs to Kafka topics, which the FR3 writers will consume.

---

## What exists

| Path | Purpose |
|---|---|
| `contracts/event.schema.json` | The frozen event contract. Simulator and API both code against this. |
| `ingest/` | FastAPI ingest service + Kafka producer |
| `processor/` | Stream processor (FR2): parse, window, dedup, detect, publish |
| `tools/mock_traffic.py` | Mock traffic: normal background + every attack scenario |
| `consumer/test_consumer.py` | Prints incoming events. Verification only. |
| `tests/smoke_test.py` | End-to-end check of ingest |
| `tests/test_processor.py` | Unit tests for the processor (pytest, no Kafka) |
| `tests/e2e_processor.py` | End-to-end check: API -> Kafka -> processor -> alerts |
| `infra/*.sh` | Kafka download, config, start/stop, topic creation |

### Kafka topics

| Topic | Partitions | Key | Purpose |
|---|---|---|---|
| `security.events.raw` | 3 | `src_ip` | All valid events |
| `security.events.dlq` | 1 | none | Payloads that failed validation (at ingest or in the processor), kept with the reason |
| `security.alerts` | 1 | entity | Detection alerts, upsert on `alert_id` |
| `security.aggregates` | 1 | `source_type` | Per-window counts and unique IPs/users, per source type |
| `security.pipeline.metrics` | 1 | none | Throughput, duplicates, late drops, lag, detection latency |

Events are keyed by `src_ip` so that all events from one source IP land on the same
partition. That preserves per-IP ordering, which is what makes per-IP brute-force
detection correct downstream without a cross-partition shuffle.

---

## Setup from a fresh clone

Requires **Java 17+** (`java -version`) and **Python 3.10+**. Tested on Ubuntu with
Java 21 and Python 3.12.

```bash
git clone <repo-url>
cd de

# 1. Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Kafka: download (~130MB), apply our config, format storage. One time only.
./infra/setup-kafka.sh
```

The Kafka distribution is **not** in git (130MB), which is why you download it. The
config that matters is tracked as `infra/server.properties.template` and applied by
the setup script.

---

## Running

Four terminals, each with `source venv/bin/activate` where Python is involved.

```bash
# Terminal 1 — Kafka broker (leave running)
./infra/start-kafka.sh

# one time, once the broker is up:
./infra/create-topics.sh

# Terminal 2 — ingest API
uvicorn ingest.main:app --reload --port 8000

# Terminal 3 — stream processor (prints alerts as they fire)
python -m processor.main
#   fast demo windows: python -m processor.main --window 10 --slide 2 --lateness 2

# Terminal 4 — mock traffic: 20s of normal activity with every attack mixed in
python -m tools.mock_traffic --scenario all
#   python -m tools.mock_traffic --list                       # scenarios and the rules they trigger
#   python -m tools.mock_traffic --scenario port_scan,api_flood --dup-rate 0.2 --late-rate 0.05
```

`python -m consumer.test_consumer` still works for watching raw events.

Watch the processor's outputs:

```bash
./infra/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic security.alerts
```

Interactive API docs: <http://127.0.0.1:8000/docs>

To stop: Ctrl-C the API and processor, then `./infra/stop-kafka.sh`.

> Existing clone? Re-run `./infra/create-topics.sh` once to create the three new output
> topics. Topic auto-creation is off, so the processor fails without them.

---

## Testing what we built

### Automated

With the broker and API running:

```bash
python -m tests.smoke_test
```

It checks health, posts 9 valid events, posts 4 deliberately broken ones, and confirms
a consumer receives exactly the 9 with each source IP on a single partition. Exits
non-zero if anything fails.

Processor unit tests (no Kafka needed):

```bash
python -m pytest tests/test_processor.py -v
```

Processor end to end (broker + API running; it starts its own processor with short
windows and a throwaway group, ~45s):

```bash
python -m tests.e2e_processor
```

It checks that each attack raises exactly its rules and normal traffic raises none,
duplicates are not double counted, late events are dropped, records the processor
rejects reach the DLQ, aggregates and metrics are published, and a restart does not
re-emit alerts.

### By hand

**A valid event — expect `202`:**

```bash
curl -X POST http://127.0.0.1:8000/events \
  -H 'Content-Type: application/json' \
  -d '{
    "event_id": "11111111-1111-1111-1111-111111111111",
    "event_time": "2026-09-11T22:30:00Z",
    "source_type": "auth",
    "src_ip": "10.0.0.5",
    "dest_ip_port": "10.0.0.1:22",
    "user": "admin",
    "status": "fail"
  }'
```

It should appear in the Terminal 3 consumer within a second.

**An invalid event — expect `422` and a DLQ entry:**

```bash
# source_type "database" is not in the allowed enum
curl -X POST http://127.0.0.1:8000/events \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"22222222-2222-2222-2222-222222222222",
       "event_time":"2026-09-11T22:30:00Z","source_type":"database",
       "src_ip":"10.0.0.5","status":"fail"}'

# then inspect what got parked:
./infra/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic security.events.dlq --from-beginning --timeout-ms 5000
```

**Useful Kafka commands:**

```bash
cd infra/kafka

# topics and their partition layout
bin/kafka-topics.sh --bootstrap-server localhost:9092 --describe

# consumer lag — CURRENT-OFFSET vs LOG-END-OFFSET
bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --describe --group test-consumer-v1
```

---

## Things that will trip you up

**`auto.offset.reset` is per partition, not per topic.** It only applies to a partition
the consumer group has *no committed offset for*. If a partition received nothing
during an earlier run, no offset was committed for it, so on restart the consumer
jumps to the end and silently skips messages already sitting there. Use
`python -m consumer.test_consumer --earliest` to replay from the beginning.

**`confluent_kafka.Consumer` is not thread-safe.** Polling it from a worker thread
while it was created elsewhere yields no messages and no error. Keep one consumer on
one thread.

**Don't re-run `kafka-storage.sh format`.** It is a one-time step and rerunning wipes
the cluster. `setup-kafka.sh` refuses to do it twice, but the raw command will not.

**Topic-name warning on create** (`topics with a period or underscore could collide`)
is expected and harmless — our names use dots only, never both.

**There is no ZooKeeper.** Kafka 4.x uses KRaft, where the broker stores its own
cluster metadata. Most tutorials online still show `zookeeper-server-start.sh`; those
are pre-4.0 and their commands will not match this setup.

---

## Design notes

- **`acks=all` + `enable.idempotence=true`** on the producer: the broker confirms every
  write and dedups producer retries, so a retry after a timeout does not become a
  second copy. Consumers can still see duplicates — that is what at-least-once means —
  which is why the stream processor will dedup on `event_id`.
- **`ingest_time` is stamped server-side** and any client value is overwritten. Producer
  clocks are not trustworthy.
- **`event_time` must carry an explicit UTC offset.** Naive timestamps are rejected at
  the door, because ambiguous timestamps make event-time windows silently wrong.
- **Unknown fields are rejected**, not ignored. A schema drift in the simulator should
  surface here at ingest, not three layers down as a broken warehouse insert.
- **Invalid payloads go to the DLQ** rather than being dropped, so bad input is evidence
  rather than a mystery.
- **`schema_version`** is on every event. Bump it if the contract changes.

## Stream processor (FR2)

Follows Lab 3 section 3, in order: parse + validate -> assign to event-time windows ->
watermark -> dedup on `event_id` -> deterministic rules.

**Windows.** Sliding, 60 s long, sliding every 10 s (`--window`, `--slide`). Stored as
10 s *panes*: each event goes into exactly one pane, and a window is its 6 consecutive
panes. This avoids copying every event into 6 windows.

**Watermark and late data.** Watermark = newest `event_time` seen minus 10 s
(`--lateness`). A window is complete once the watermark passes its end. An event whose
windows have all been emitted is dropped and counted as `late`. If the topic is idle
for 5 s (`--idle-advance`), the watermark follows the wall clock so the last windows
still close. Events more than 60 s in the future (`MAX_FUTURE_S`) go to the DLQ: a
broken clock would otherwise push the watermark forward and make honest events late.

**Dedup.** A set of `event_id`s for the open windows only. Once every window an id
could belong to has closed, a duplicate of it would be late anyway, so the id is
forgotten. Memory stays bounded by the window length.

**Cleaning.** IPs are canonicalised (`ipaddress`), usernames are trimmed and
lowercased, `dest_ip_port` is split into `dest_ip` + `dest_port` (IPv6 `[::1]:443`
supported). Unparseable records go to the DLQ with `stage: stream-processor`.

**Rules** (`processor/rules.py`; thresholds can be overridden with `RULE_<NAME>_THRESHOLD`):

| Rule | Looks at | Key | Fires when (per window) | Severity |
|---|---|---|---|---|
| `brute_force` | auth, not success | src_ip + user | >= 5 failures | high |
| `password_spray` | auth, not success | src_ip | >= 5 distinct users | high |
| `brute_force_success` | auth | src_ip + user | >= 5 failures then a success | critical |
| `distributed_brute_force` | auth, not success | user | >= 5 distinct source IPs | high |
| `port_scan` | network | src_ip + dest_ip | >= 10 distinct ports | medium |
| `host_sweep` | network | src_ip | >= 10 distinct dest hosts | medium |
| `api_flood` | api | src_ip | >= 50 requests | medium |
| `api_access_probing` | api, not success | src_ip | >= 10 denied/failed | medium |

At 3x the threshold an alert goes up one severity level.

**Alert timing.** Every rule measures something that only grows (a count, a number of
distinct values), so an alert is raised the moment the threshold is crossed (`trigger:
early`, typically under 0.5 s after ingest), not when the window closes. When the
window closes, the alert is re-sent with its final count (`trigger: final`) under the
same `alert_id`. While one window has alerted for a (rule, key), overlapping windows
for the same pair are suppressed, so one attack gives one alert rather than six.

**Provenance.** Each alert carries `sample_event_ids` (up to 10 of the raw events
behind it), the window bounds, the first and last `event_time`, `detected_at`,
`detection_latency_ms`, and the processor's group and window settings.

**Delivery and restart.** At-least-once. Offsets are committed by hand: only up to the
oldest event still in an open window, and only after Kafka has acknowledged every
output. The commit metadata records which windows were already emitted. After a crash
the processor rebuilds the open windows from Kafka without re-emitting closed ones.
`alert_id` is a deterministic UUID of (rule, entity, window), so replays upsert.

**Single instance.** Run one processor. The watermark and `distributed_brute_force`
(keyed by user, not by the `src_ip` partition key) need to see every partition.

### Open question

Lab 3 names the field `dest_ip:port`. A colon is awkward as a JSON key, so it is
`dest_ip_port` here, holding the same `"ip:port"` string. The processor now splits it
itself, so the contract can stay as is. Changing it is optional.
