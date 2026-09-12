import asyncio
import logging
from typing import Optional, Dict, Any
import httpx
from simulator.models import SecurityEvent

logger = logging.getLogger("simulator.dispatcher")

class EventDispatcher:
    """Dispatches generated security events to the target Python Event API over HTTP."""

    def __init__(self, target_url: str = "http://localhost:8000/api/v1/events", forward_enabled: bool = False):
        self.target_url = target_url
        self.forward_enabled = forward_enabled
        self._client: Optional[httpx.AsyncClient] = None
        self.total_dispatched = 0
        self.total_failed = 0
        self.last_error: Optional[str] = None

    async def start(self):
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=3.0)

    async def stop(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def dispatch(self, event: SecurityEvent) -> bool:
        if not self.forward_enabled:
            # Standalone simulator mode: event stays internal for UI visualization
            return True

        if self._client is None or self._client.is_closed:
            await self.start()

        # Strictly output payload with alias 'dest_ip:port'
        payload = event.model_dump(by_alias=True)

        try:
            resp = await self._client.post(self.target_url, json=payload)
            if resp.status_code in [200, 201, 202]:
                self.total_dispatched += 1
                return True
            else:
                self.total_failed += 1
                self.last_error = f"HTTP {resp.status_code}: {resp.text[:100]}"
                return False
        except Exception as e:
            self.total_failed += 1
            self.last_error = str(e)
            return False

    def get_stats(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "forward_enabled": self.forward_enabled,
            "total_dispatched": self.total_dispatched,
            "total_failed": self.total_failed,
            "last_error": self.last_error
        }
