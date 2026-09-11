"""Ingest API: the HTTP front door the Attack Simulator (FR1) posts events to.

Flow: validate -> stamp ingest_time -> produce to Kafka keyed on src_ip -> 202.
Anything that fails validation goes to the DLQ and returns 422, so a malformed
event from the simulator is preserved for inspection instead of vanishing.
"""
import logging
from contextlib import asynccontextmanager

from confluent_kafka import KafkaException
from confluent_kafka.admin import AdminClient
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .config import KAFKA_BOOTSTRAP, TOPIC_DLQ, TOPIC_RAW
from .producer import flush, get_producer, publish_dlq, publish_event
from .schema import SecurityEvent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ingest")


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_producer()
    log.info("ingest API up, producing to %s via %s", TOPIC_RAW, KAFKA_BOOTSTRAP)
    yield
    pending = flush()
    if pending:
        log.warning("shut down with %d messages undelivered", pending)


app = FastAPI(
    title="Security Event Ingest API",
    description="Group 4 - Real-Time Cybersecurity Event Analytics Platform",
    version="1.0.0",
    lifespan=lifespan,
)


def _serialisable_errors(exc: RequestValidationError) -> list[dict]:
    """Flatten Pydantic errors into something JSONResponse can encode.

    A ValueError raised inside a custom @field_validator arrives here as a live
    exception object under ctx['error'], which is not JSON serialisable and would
    turn a 422 into a 500. Stringify anything exotic.
    """
    clean = []
    for err in exc.errors():
        e = {
            "type": err.get("type"),
            "loc": [str(part) for part in err.get("loc", ())],
            "msg": str(err.get("msg", "")),
        }
        ctx = err.get("ctx")
        if ctx:
            e["ctx"] = {k: str(v) for k, v in ctx.items()}
        clean.append(e)
    return clean


@app.exception_handler(RequestValidationError)
async def on_validation_error(request: Request, exc: RequestValidationError):
    """Send invalid payloads to the DLQ rather than dropping them.

    FastAPI would normally just return 422. We want the bad payload retained: a
    schema drift in the simulator is a real finding, and the DLQ is the evidence.
    """
    body = await request.body()
    errors = _serialisable_errors(exc)
    publish_dlq(body, str(errors))
    log.warning("invalid event -> DLQ: %s", errors)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": errors, "note": f"payload parked in {TOPIC_DLQ}"},
    )


@app.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(event: SecurityEvent):
    """Accept one security event.

    202, not 200: we have handed the event to Kafka, we have not yet processed it.
    """
    payload = event.to_kafka_dict()
    try:
        publish_event(payload, key=event.src_ip)
    except (BufferError, KafkaException) as exc:
        # Local queue full or broker unreachable. Tell the simulator to back off
        # rather than silently dropping -- this is the FR1 "generator might drop
        # events under heavy load" risk, handled as backpressure.
        log.error("produce failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "ingest backpressure, retry shortly"},
        )
    return {"status": "accepted", "event_id": str(event.event_id),
            "ingest_time": payload["ingest_time"]}


@app.get("/health")
async def health():
    """Liveness + broker reachability, so a demo failure is diagnosable at a glance."""
    try:
        md = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP}).list_topics(timeout=5)
        topics = [t for t in (TOPIC_RAW, TOPIC_DLQ) if t in md.topics]
        return {
            "status": "ok" if len(topics) == 2 else "degraded",
            "broker": KAFKA_BOOTSTRAP,
            "brokers_up": len(md.brokers),
            "topics_found": topics,
        }
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "kafka unreachable", "error": str(exc)},
        )
