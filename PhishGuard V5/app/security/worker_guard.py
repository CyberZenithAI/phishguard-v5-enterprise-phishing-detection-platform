# app/security/worker_guard.py

from __future__ import annotations

import asyncio
import logging
import signal
from contextlib import suppress

LOGGER = logging.getLogger(__name__)


class WorkerGuard:

    def __init__(
        self,
        timeout: int = 120,
        concurrency_limit: int = 100,
    ) -> None:

        self.timeout = timeout

        self.semaphore = asyncio.Semaphore(concurrency_limit)

        signal.signal(signal.SIGTERM, self.shutdown_handler)

    async def execute(self, coro):

        async with self.semaphore:

            return await asyncio.wait_for(
                coro,
                timeout=self.timeout,
            )

    @staticmethod
    def shutdown_handler(signum, frame):

        LOGGER.warning(
            "worker_shutdown_signal_received",
            extra={
                "signal": signum
            }
        )

        tasks = asyncio.all_tasks()

        for task in tasks:
            task.cancel()
