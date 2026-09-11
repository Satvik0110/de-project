# Real-Time Cybersecurity Event Analytics Platform — Ingestion Layer

Group 4 (B23EE1094, B23ES1032, B23EE1041)

This repo currently contains the **ingestion layer**: the HTTP event API, the Kafka
topics behind it, and a test consumer used to verify events flow end to end.

```
Attack Simulator  --HTTP-->  Ingest API  --produce-->  Kafka  --consume-->  Stream Processor
   (FR1, Maulik)              [this repo]            [this repo]              (FR2, next)
```

The stream processor (FR2), Parquet data lake and PostgreSQL warehouse (FR3) are not
built yet. The test consumer here only prints events; it does no windowing, dedup or
storage.

---

## What exists

| Path | Purpose |
|---|---|
| `contracts/event.schema.json` | The frozen event contract. Simulator and API both code against this. |
| `ingest/` | FastAPI ingest service + Kafka producer |
| `consumer/test_consumer.py` | Prints incoming events. Verification only, not FR2. |
| `tests/smoke_test.py` | One-command end-to-end check |
| `infra/*.sh` | Kafka download, config, start/stop, topic creation |

### Kafka topics

| Topic | Partitions | Key | Purpose |
|---|---|---|---|
| `security.events.raw` | 3 | `src_ip` | All valid events |
| `security.events.dlq` | 1 | none | Payloads that failed validation, kept with the reason |

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

Three terminals, each with `source venv/bin/activate` where Python is involved.

```bash
# Terminal 1 — Kafka broker (leave running)
./infra/start-kafka.sh

# one time, once the broker is up:
./infra/create-topics.sh

# Terminal 2 — ingest API
uvicorn ingest.main:app --reload --port 8000

# Terminal 3 — test consumer
python -m consumer.test_consumer
```

Interactive API docs: <http://127.0.0.1:8000/docs>

To stop: Ctrl-C the API and consumer, then `./infra/stop-kafka.sh`.

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

### Open question

Lab 3 names the field `dest_ip:port`. A colon is awkward as a JSON key, so it is
`dest_ip_port` here, holding the same `"ip:port"` string. Splitting it into `dest_ip`
and `dest_port` would make port-scan detection (counting distinct ports) easier
downstream — worth deciding before the simulator hardcodes the current shape.
