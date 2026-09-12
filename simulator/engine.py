import asyncio
import logging
import time
from collections import deque
from typing import Set, Dict, Any, Optional, List

from fastapi import WebSocket

from simulator.models import SecurityEvent, SimulatorConfig, AttackTriggerRequest
from simulator.scenarios import ScenarioEngine
from simulator.dispatcher import EventDispatcher

logger = logging.getLogger("simulator.engine")


class SimulatorEngine:
    """
    Core attack orchestrator.

    Drives the ScenarioEngine (real HTTP attack engine) at the configured EPS rate.
    Collects events built from real HTTP responses and broadcasts them to WebSocket
    subscribers and optionally forwards them to the downstream event API.
    """

    def __init__(self):
        self.config = SimulatorConfig()
        self.scenario_engine = ScenarioEngine()   # real HTTP attack engine
        self.dispatcher = EventDispatcher()

        self._task: Optional[asyncio.Task] = None
        self._subscribers: Set[WebSocket] = set()
        self.recent_events: deque = deque(maxlen=200)

        # Telemetry counters
        self.total_generated = 0
        self.type_counts = {"auth": 0, "network": 0, "api": 0}
        self.status_counts = {"ok": 0, "invalid": 0}
        self.attack_events_count = 0

        # EPS measurement
        self._second_counter = 0
        self._last_second_time = time.time()
        self.current_eps = 0.0

    # ── Config ────────────────────────────────────────────────────────────────

    async def update_config(self, new_config: SimulatorConfig):
        old_running = self.config.running
        self.config = new_config
        self.dispatcher.target_url = new_config.target_api_url
        self.dispatcher.forward_enabled = new_config.forward_to_target

        if self.config.running and not old_running:
            self.start_loop()
        elif not self.config.running and old_running:
            self.stop_loop()

    # ── Loop control ──────────────────────────────────────────────────────────

    def start_loop(self):
        self.config.running = True
        if self._task is None or self._task.done():
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self._run_loop())

    def stop_loop(self):
        self.config.running = False
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None

    # ── Reset ─────────────────────────────────────────────────────────────────

    async def reset_state(self):
        """Reset all counters and notify connected WebSocket subscribers."""
        self.stop_loop()
        self.recent_events.clear()
        self.total_generated = 0
        self.type_counts = {"auth": 0, "network": 0, "api": 0}
        self.status_counts = {"ok": 0, "invalid": 0}
        self.attack_events_count = 0
        self.current_eps = 0.0
        self._second_counter = 0
        self.dispatcher.total_dispatched = 0
        self.dispatcher.total_failed = 0
        self.dispatcher.last_error = None

        if self._subscribers:
            msg = {"type": "RESET_STATE", "stats": self.get_stats(), "recent_events": []}
            stale = set()
            for ws in list(self._subscribers):
                try:
                    await ws.send_json(msg)
                except Exception:
                    stale.add(ws)
            self._subscribers -= stale

    # ── Attack burst ──────────────────────────────────────────────────────────

    async def trigger_attack(self, req: AttackTriggerRequest) -> List[SecurityEvent]:
        """
        Fire a burst of real HTTP attacks at the target.
        Each iteration sends an actual request and waits for the real response.
        """
        events: List[SecurityEvent] = []
        target_url = self.config.target_base_url
        target_user = req.target_user or self.config.target_user

        logger.info(
            f"Triggering attack burst: scenario={req.scenario!r}  "
            f"count={req.burst_count}  target={target_url!r}  user={target_user!r}"
        )

        for _ in range(req.burst_count):
            ev = await self.scenario_engine.trigger_named_attack(
                scenario_name=req.scenario,
                target_url=target_url,
                target_user=target_user,
            )
            await self._process_event(ev, is_attack=True)
            events.append(ev)
            # Small delay so we don't overwhelm the event loop or the target
            await asyncio.sleep(0.02)

        return events

    # ── Continuous loop ────────────────────────────────────────────────────────

    async def _run_loop(self):
        """
        Continuous real-attack loop.
        Sends one real HTTP request per iteration at the configured EPS rate.
        """
        while self.config.running:
            try:
                target_eps = max(0.5, self.config.events_per_second)
                interval = 1.0 / target_eps
                start = time.time()

                ev = await self.scenario_engine.generate_random_event(
                    target_url=self.config.target_base_url,
                    target_user=self.config.target_user,
                    only_attacks=self.config.only_attacks,
                    selected_scenarios=self.config.selected_scenarios,
                    attack_ratio=self.config.attack_ratio,
                )
                is_attack = ev.raw_payload.get("threat_flag") == "malicious"
                await self._process_event(ev, is_attack=is_attack)

                elapsed = time.time() - start
                sleep_time = max(0.001, interval - elapsed)
                await asyncio.sleep(sleep_time)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Run loop error: {exc}")
                await asyncio.sleep(0.1)

    # ── Event processing ───────────────────────────────────────────────────────

    async def _process_event(self, event: SecurityEvent, is_attack: bool = False):
        """Update counters, buffer the event, dispatch it, and broadcast to WebSockets."""
        self.total_generated += 1
        self.type_counts[event.source_type] = self.type_counts.get(event.source_type, 0) + 1
        self.status_counts[event.status] = self.status_counts.get(event.status, 0) + 1
        if is_attack:
            self.attack_events_count += 1

        # EPS measurement
        self._second_counter += 1
        now = time.time()
        if now - self._last_second_time >= 1.0:
            self.current_eps = round(
                self._second_counter / (now - self._last_second_time), 1
            )
            self._second_counter = 0
            self._last_second_time = now

        event_dict = event.model_dump(by_alias=True)
        self.recent_events.append(event_dict)

        # Forward to downstream event API asynchronously (non-blocking)
        asyncio.create_task(self.dispatcher.dispatch(event))

        # Broadcast to all connected WebSocket subscribers
        if self._subscribers:
            msg = {"type": "NEW_EVENT", "event": event_dict, "stats": self.get_stats()}
            stale = set()
            for ws in list(self._subscribers):
                try:
                    await ws.send_json(msg)
                except Exception:
                    stale.add(ws)
            self._subscribers -= stale

    # ── WebSocket subscribers ─────────────────────────────────────────────────

    async def register_subscriber(self, ws: WebSocket):
        await ws.accept()
        self._subscribers.add(ws)
        await ws.send_json({
            "type": "INITIAL_STATE",
            "config": self.config.model_dump(),
            "stats": self.get_stats(),
            "recent_events": list(self.recent_events),
        })

    def unregister_subscriber(self, ws: WebSocket):
        self._subscribers.discard(ws)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        return {
            "running": self.config.running,
            "current_eps": self.current_eps,
            "target_eps": self.config.events_per_second,
            "attack_ratio": self.config.attack_ratio,
            "total_generated": self.total_generated,
            "attack_events_count": self.attack_events_count,
            "type_counts": self.type_counts,
            "status_counts": self.status_counts,
            "dispatcher": self.dispatcher.get_stats(),
            "active_subscribers": len(self._subscribers),
        }
