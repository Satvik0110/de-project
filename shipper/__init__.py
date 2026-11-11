"""Log shipper: forwards security events from a defended system to the ingest API.

Plays the role Filebeat / Fluent Bit play in a real deployment. The defended systems
(target web app, network sensor) write the security log; the attacker never does.

  emit() -> bounded queue -> workers -> POST /events, retried with backoff on 503
            and connection errors (ingest backpressure). At-least-once, like real shippers.

"Unreliable network" (chaos) mode reproduces what real shippers do under failure, so the
stream processor's dedup and lateness handling can be demonstrated live:
  - a retry after a lost ack re-sends an event        -> duplicate event_id
  - a buffered batch is flushed a few seconds late    -> out of order, still in time
  - a backlog is flushed after a long outage          -> too late, dropped by the watermark
"""
import asyncio
import logging
import os
import random
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

import httpx

INGEST_URL = os.getenv("INGEST_URL", "http://127.0.0.1:8000/events")
DUP_RATE, DELAY_RATE, DELAY_S = 0.10, 0.10, (2.0, 8.0)
LATE_RATE, LATE_S = 0.02, 90.0          # > window (60 s) + lateness (10 s): always late

log = logging.getLogger("shipper")


def make_event(source_type: str, src_ip: str, status: str, dest: Optional[str] = None,
               user: Optional[str] = None, raw: Optional[dict] = None) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "event_time": datetime.now(timezone.utc).isoformat(),
        "source_type": source_type,
        "src_ip": src_ip,
        "dest_ip_port": dest,
        "user": user,
        "status": status,
        "raw_payload": raw,
    }


class LogShipper:
    def __init__(self, name: str, workers: int = 8, max_queue: int = 10_000):
        self.name, self.workers = name, workers
        self.queue: asyncio.Queue = asyncio.Queue(max_queue)
        self.chaos = False
        self.stats: Counter = Counter()
        self._tasks: list[asyncio.Task] = []
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=5.0)
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(self.workers)]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        if self._client:
            await self._client.aclose()

    def emit(self, event: dict) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            # Bounded memory: a real shipper would spill to disk. Counted, never silent.
            self.stats["dropped_queue_full"] += 1

    async def _worker(self) -> None:
        while True:
            ev = await self.queue.get()
            if self.chaos:
                r = random.random()
                if r < LATE_RATE:
                    self._later(ev, LATE_S)
                    self.stats["chaos_late"] += 1
                    continue
                if r < LATE_RATE + DELAY_RATE:
                    self._later(ev, random.uniform(*DELAY_S))
                    self.stats["chaos_delayed"] += 1
                    continue
                if r < LATE_RATE + DELAY_RATE + DUP_RATE:
                    self._later(ev, random.uniform(0.1, 1.0))
                    self.stats["chaos_duplicated"] += 1
            await self._send(ev)

    def _later(self, ev: dict, delay: float) -> None:
        async def go():
            await asyncio.sleep(delay)
            await self._send(ev)
        asyncio.create_task(go())

    async def _send(self, ev: dict) -> None:
        backoff = 0.2
        for _ in range(6):
            try:
                r = await self._client.post(INGEST_URL, json=ev)
                if r.status_code == 202:
                    self.stats["sent"] += 1
                    return
                if r.status_code != 503:
                    self.stats["rejected"] += 1
                    log.warning("%s: ingest rejected event (%s): %s", self.name, r.status_code, r.text[:200])
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 3.0)
        self.stats["failed"] += 1
