"""Kafka producer wrapper.

Settings here are the ones that back the delivery guarantees claimed in Lab 3:
  acks=all           -- broker confirms the write before we count it as delivered
  enable.idempotence -- the broker dedups producer retries, so a retry after a
                        timeout does not become a second copy of the event
Together these give at-least-once ingest without producer-side duplicates.
Duplicates can still reach the consumer (that is what at-least-once means), which
is why the stream processor dedups on event_id.
"""
import json
import logging
from typing import Any, Optional

from confluent_kafka import Producer

from .config import KAFKA_BOOTSTRAP, TOPIC_DLQ, TOPIC_RAW

log = logging.getLogger(__name__)

_producer: Optional[Producer] = None


def _on_delivery(err, msg) -> None:
    """Async delivery callback. Fires once Kafka acks (or gives up on) a message."""
    if err is not None:
        log.error("DELIVERY FAILED topic=%s: %s", msg.topic() if msg else "?", err)
    else:
        log.debug(
            "delivered topic=%s partition=%s offset=%s",
            msg.topic(), msg.partition(), msg.offset(),
        )


def get_producer() -> Producer:
    global _producer
    if _producer is None:
        _producer = Producer({
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "acks": "all",
            "enable.idempotence": True,
            # Batch briefly instead of sending one request per event. Costs up to
            # 10ms of latency, buys a large throughput win during attack bursts.
            "linger.ms": 10,
            "compression.type": "lz4",
            # Bound the local queue. librdkafka's produce() never blocks: once this
            # is full it raises BufferError immediately, which the API turns into a
            # 503. That is the backpressure signal, in place of the Java client's
            # max.block.ms (librdkafka has no such property).
            "queue.buffering.max.messages": 100000,
            "client.id": "ingest-api",
        })
    return _producer


def publish_event(event: dict[str, Any], key: str) -> None:
    """Produce a validated event to the raw topic, keyed by src_ip.

    Keying matters: same key -> same partition -> events from one source IP stay in
    order and land on one consumer. That is what makes per-IP brute-force counting
    correct without a cross-partition shuffle.
    """
    p = get_producer()
    p.produce(
        topic=TOPIC_RAW,
        key=key.encode("utf-8"),
        value=json.dumps(event).encode("utf-8"),
        on_delivery=_on_delivery,
    )
    # Serve queued delivery callbacks without blocking on the network.
    p.poll(0)


def publish_dlq(raw_body: bytes, reason: str) -> None:
    """Park an unparseable/invalid payload for later inspection.

    Best-effort by design: if the DLQ write itself fails we log and move on rather
    than failing the request a second time.
    """
    p = get_producer()
    try:
        p.produce(
            topic=TOPIC_DLQ,
            value=json.dumps({
                "reason": reason,
                "raw_body": raw_body.decode("utf-8", errors="replace"),
            }).encode("utf-8"),
            on_delivery=_on_delivery,
        )
        p.poll(0)
    except Exception:
        log.exception("could not write to DLQ")


def flush(timeout: float = 10.0) -> int:
    """Block until queued messages are delivered. Returns count still pending."""
    return get_producer().flush(timeout)
