# app/security/memory_guard.py

from __future__ import annotations

import gc
import logging
import tracemalloc

LOGGER = logging.getLogger(__name__)


class MemoryGuard:

    def __init__(
        self,
        memory_limit_mb: int = 512,
    ) -> None:

        self.memory_limit = memory_limit_mb * 1024 * 1024

        tracemalloc.start()

    def monitor(self) -> None:

        current, peak = tracemalloc.get_traced_memory()

        if current >= self.memory_limit:

            LOGGER.critical(
                "memory_limit_reached",
                extra={
                    "current": current,
                    "peak": peak,
                }
            )

            gc.collect()

    @staticmethod
    def optimize_gc() -> None:

        gc.set_threshold(
            700,
            10,
            10,
        )
