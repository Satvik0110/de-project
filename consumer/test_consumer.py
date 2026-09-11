"""Throwaway consumer, for verifying ingest only.

Prints every event it receives with its partition and offset. It is NOT the
stream processor (FR2) -- no windowing, no dedup, no storage. It exists to answer
one question: are events actually arriving, keyed and ordered as designed?

Note the group id: 'test-consumer-v1', deliberately not the 'stream-processor-v1'
group the real processor will use, so testing here does not move that group's
offsets.

Usage:
    python -m consumer.test_consumer            # from the last committed offset
    python -m consumer.test_consumer --earliest # replay from the start
"""
import argparse
import json
import signal
import sys

from confluent_kafka import Consumer, KafkaError, KafkaException

BOOTSTRAP = "localhost:9092"
TOPIC = "security.events.raw"
GROUP = "test-consumer-v1"

running = True


def stop(signum, frame):
    global running
    running = False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--earliest", action="store_true",
                    help="start from the beginning if this group has no committed offset")
    args = ap.parse_args()

    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP,
        "group.id": GROUP,
        "auto.offset.reset": "earliest" if args.earliest else "latest",
        # Commit manually, AFTER we have handled the message. This is what makes
        # at-least-once real: crash before the commit and the event is redelivered
        # rather than lost. The real processor will commit only after its writes
        # to the lake and warehouse succeed.
        "enable.auto.commit": False,
    })
    consumer.subscribe([TOPIC])

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    print(f"consuming {TOPIC} as group '{GROUP}' -- Ctrl-C to stop\n")
    print(f"{'PART':<5} {'OFFSET':<8} {'KEY (src_ip)':<18} {'EVENT_ID':<38} SOURCE/STATUS")
    print("-" * 100)

    count = 0
    try:
        while running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                raise KafkaException(msg.error())

            key = msg.key().decode() if msg.key() else "-"
            try:
                ev = json.loads(msg.value())
                summary = f"{ev.get('source_type', '?')}/{ev.get('status', '?')}"
                eid = ev.get("event_id", "?")
            except json.JSONDecodeError:
                summary, eid = "UNPARSEABLE", "?"

            print(f"{msg.partition():<5} {msg.offset():<8} {key:<18} {eid:<38} {summary}")
            count += 1
            consumer.commit(msg, asynchronous=False)
    finally:
        consumer.close()
        print(f"\nconsumed {count} event(s), offsets committed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
