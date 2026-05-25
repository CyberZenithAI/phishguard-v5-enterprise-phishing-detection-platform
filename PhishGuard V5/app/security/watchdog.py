# app/security/watchdog.py

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class WatchdogState:
    last_heartbeat: float
    failures: int


class Watchdog:

    def __init__(
        self,
        timeout: int = 60,
    ) -> None:

        self.timeout = timeout

        self.state = WatchdogState(
            last_heartbeat=time.time(),
            failures=0,
        )

    async def heartbeat(self) -> None:

        self.state.last_heartbeat = time.time()

    async def monitor(self) -> None:

        while True:

            await asyncio.sleep(10)

            delta = time.time() - self.state.last_heartbeat

            if delta > self.timeout:

                self.state.failures += 1

                LOGGER.critical(
                    "watchdog_timeout",
                    extra={
                        "delta": delta,
                        "failures": self.state.failures,
                    }
                )
