"""Stream processor (FR2): consume raw events, detect attacks, publish alerts.

    security.events.raw --> parse/validate --> windows + watermark --> dedup --> rules
                                 |                                               |
                                 v                                               v
                        security.events.dlq                  security.alerts, security.aggregates
                                                             security.pipeline.metrics

Delivery: at-least-once. Offsets are committed by hand, only up to the oldest event
still held in an open window, and only after every alert/aggregate produced so far
has been acknowledged by Kafka. A crash therefore replays from Kafka and rebuilds
the open windows instead of losing them. Replays can re-emit an alert; it carries the
same deterministic alert_id, so downstream writes should upsert on it.

Run ONE instance. The watermark and the per-user rule (distributed_brute_force) need
to see all partitions; a second instance in the same group would split them.

Usage:
    python -m processor.main
    python -m processor.main --window 10 --slide 2 --lateness 2   # fast demo windows
"""
import argparse
import json
import logging
import signal
import sys
import time
from collections import Counter, deque

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer, TopicPartition

from . import config
from .engine import WindowEngine, iso
from .model import InvalidEvent, parse_event
from .rules import default_rules

log = logging.getLogger("processor")

running = True


def stop(signum, frame):
    global running
    running = False


class Outputs:
    """Kafka producer for everything the processor emits, with delivery tracking."""

    def __init__(self):
        self.producer = Producer({
            "bootstrap.servers": config.KAFKA_BOOTSTRAP,
            "acks": "all",
            "enable.idempotence": True,
            "linger.ms": 5,
            "client.id": "stream-processor",
        })
        self.failed = 0

    def _on_delivery(self, err, msg):
        if err is not None:
            self.failed += 1
            log.error("DELIVERY FAILED topic=%s: %s", msg.topic() if msg else "?", err)

    def send(self, topic: str, value: dict, key: str = None):
        self.producer.produce(topic, key=key.encode() if key else None,
                              value=json.dumps(value).encode(), on_delivery=self._on_delivery)
        self.producer.poll(0)

    def flush(self, timeout: float = 10.0) -> bool:
        """True once everything sent so far is acknowledged."""
        return self.producer.flush(timeout) == 0 and self.failed == 0


def pct(values, *qs) -> dict:
    """Nearest-rank percentiles, e.g. pct(xs, 50, 95) -> {"p50": .., "p95": ..}."""
    v = sorted(values)
    return {f"p{q}": round(v[min(len(v) - 1, int(q / 100 * len(v)))], 1) for q in qs}


def print_alert(a: dict) -> None:
    lat = f"{a['detection_latency_ms']:.0f}ms" if a.get("detection_latency_ms") is not None else "-"
    print(f"ALERT [{a['severity'].upper():<8}] {a['rule_name']:<24} {a['entity']:<40} "
          f"count={a['count']}/{a['threshold']}  window {a['window_start'][11:19]}-"
          f"{a['window_end'][11:19]}  {a['trigger']:<9} latency={lat}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--group", default=config.GROUP_ID)
    ap.add_argument("--window", type=int, default=config.WINDOW_S, help="window length, seconds")
    ap.add_argument("--slide", type=int, default=config.SLIDE_S, help="window slide, seconds")
    ap.add_argument("--lateness", type=float, default=config.LATENESS_S, help="allowed lateness, seconds")
    ap.add_argument("--idle-advance", type=float, default=config.IDLE_ADVANCE_S,
                    help="seconds of no input before the watermark follows the wall clock")
    ap.add_argument("--latest", action="store_true",
                    help="with no committed offsets, start at the end of the topic instead of the beginning")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    info = {"group": args.group, "window_s": args.window, "slide_s": args.slide,
            "lateness_s": args.lateness}
    engine = WindowEngine(default_rules(), args.window, args.slide, args.lateness,
                          config.SAMPLE_IDS_PER_ALERT, processor_info=info)
    out = Outputs()

    consumer = Consumer({
        "bootstrap.servers": config.KAFKA_BOOTSTRAP,
        "group.id": args.group,
        # Unlike the test consumer, default to earliest: the processor must not
        # silently skip events that arrived before its first run.
        "auto.offset.reset": "latest" if args.latest else "earliest",
        "enable.auto.commit": False,
    })

    def on_assign(c, partitions):
        committed = c.committed(partitions, timeout=10)
        for tp in committed:
            if tp.metadata:
                cp = json.loads(tp.metadata)
                if (cp.get("window_s"), cp.get("slide_s")) == (args.window, args.slide):
                    engine.restore(cp["closed_before"])
        log.info("assigned partitions %s, resuming at offsets %s%s",
                 [tp.partition for tp in partitions], [tp.offset for tp in committed],
                 f", windows before {iso(engine.next_start * args.slide)} already emitted"
                 if engine.next_start is not None else "")

    consumer.subscribe([config.TOPIC_RAW], on_assign=on_assign)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    log.info("processing %s as group '%s': window=%ss slide=%ss lateness=%ss, %d rules",
             config.TOPIC_RAW, args.group, args.window, args.slide, args.lateness, len(engine.rules))

    def commit() -> None:
        # Outputs first, offsets second: committing before Kafka has the alerts
        # would turn a crash into lost alerts.
        if not out.flush():
            log.error("outputs not acknowledged, NOT committing offsets")
            raise SystemExit(2)
        offsets = engine.committable_offsets()
        if offsets:
            meta = engine.checkpoint()
            consumer.commit(offsets=[TopicPartition(config.TOPIC_RAW, p, o, metadata=meta)
                                     for p, o in offsets.items()], asynchronous=False)

    def emit_alert(a: dict) -> None:
        out.send(config.TOPIC_ALERTS, a, key=a["entity"])
        print_alert(a)
        if a["trigger"] == "early" and a["detection_latency_ms"] is not None:
            latencies.append(a["detection_latency_ms"])

    # Detection latency over the last 500 alerts (alerts are bursty; a per-interval figure
    # would be empty most of the time). Stage latencies are per interval, sampled per event:
    #   ingest     = ingest_time - event_time   (source -> log shipper -> ingest API)
    #   processing = processed   - ingest_time  (Kafka + processor queueing)
    latencies: deque = deque(maxlen=500)
    ingest_ms: list[float] = []
    processing_ms: list[float] = []
    last_input = last_commit = last_metrics = time.time()
    prev_stats: Counter = Counter()

    try:
        while running:
            # consume() returns early once 500 records are ready, so the timeout only bounds the
            # wait at low rates: it sits directly on detection latency, so keep it short.
            msgs = consumer.consume(num_messages=500, timeout=0.1)
            now = time.time()
            if msgs:
                last_input = now

            for msg in msgs:
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    raise KafkaException(msg.error())
                try:
                    ev = parse_event(msg.value(), now, config.MAX_FUTURE_S)
                except InvalidEvent as exc:
                    engine.stats["invalid"] += 1
                    engine.note_offset(msg.partition(), msg.offset())
                    out.send(config.TOPIC_DLQ, {
                        "reason": str(exc), "stage": "stream-processor",
                        "source": {"topic": msg.topic(), "partition": msg.partition(),
                                   "offset": msg.offset()},
                        "raw_body": (msg.value() or b"").decode("utf-8", errors="replace"),
                    })
                    log.warning("invalid record p%s@%s -> DLQ: %s", msg.partition(), msg.offset(), exc)
                    continue
                if ev.ingest_ts:
                    ingest_ms.append((ev.ingest_ts - ev.ts) * 1000)
                    processing_ms.append((now - ev.ingest_ts) * 1000)
                for a in engine.add(ev, now, msg.partition(), msg.offset()):
                    emit_alert(a)

            if not msgs and now - last_input >= args.idle_advance:
                engine.advance_wallclock(now)

            final_alerts, aggregates = engine.close_ready(now)
            for a in final_alerts:
                emit_alert(a)
            for row in aggregates:
                out.send(config.TOPIC_AGGREGATES, row, key=row["source_type"])

            if now - last_commit >= config.COMMIT_INTERVAL_S:
                commit()
                last_commit = now

            if now - last_metrics >= config.METRICS_INTERVAL_S:
                elapsed = now - last_metrics
                delta = engine.stats - prev_stats
                lag = 0
                for tp in consumer.assignment():
                    _, high = consumer.get_watermark_offsets(tp, timeout=2)
                    pos = consumer.position([tp])[0].offset
                    lag += max(high - pos, 0) if pos >= 0 else 0
                m = {
                    "at": iso(now), "group": args.group, "interval_s": round(elapsed, 1),
                    "events_per_s": round((delta["accepted"] + delta["duplicate"] + delta["late"]
                                           + delta["invalid"]) / elapsed, 1),
                    "totals": {**dict.fromkeys(("accepted", "duplicate", "late", "invalid", "alerts"), 0),
                               **engine.stats},
                    "interval": dict(delta),
                    "watermark": iso(engine.watermark) if engine.watermark > 0 else None,
                    "watermark_delay_s": round(now - engine.watermark, 1) if engine.watermark > 0 else None,
                    "consumer_lag": lag,
                    "detection_latency_ms": {
                        **pct(latencies, 50, 95, 99), "max": round(max(latencies), 1), "n": len(latencies),
                    } if latencies else None,
                    "stage_latency_ms": {
                        "ingest": pct(ingest_ms, 50, 95), "processing": pct(processing_ms, 50, 95),
                    } if ingest_ms else None,
                    "alerts_by_rule": dict(engine.alerts_by_rule),
                    **engine.state_size(),
                }
                out.send(config.TOPIC_METRICS, m)
                log.info("metrics: %.1f ev/s | %s | lag=%d | %s", m["events_per_s"],
                         ", ".join(f"{k}={v}" for k, v in sorted(m["totals"].items())),
                         lag, engine.state_size())
                prev_stats, last_metrics = Counter(engine.stats), now
                ingest_ms, processing_ms = [], []
    finally:
        try:
            commit()
            log.info("final commit done: %s", engine.committable_offsets())
        finally:
            consumer.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
