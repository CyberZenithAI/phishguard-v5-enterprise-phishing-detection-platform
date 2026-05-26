# app/worker/worker.py

import os
import json
import asyncio
import random
import time
import uuid
import signal
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any

import redis.asyncio as redis

# =========================
# CONFIG
# =========================

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
QUEUE_NAME = "queue"
DLQ_NAME = "queue_dlq"

MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))
BASE_BACKOFF = float(os.getenv("BASE_BACKOFF", "0.5"))
MAX_BACKOFF = float(os.getenv("MAX_BACKOFF", "10"))

CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "5"))

# =========================
# LOGGING (STRUCTURED JSON)
# =========================

logger = logging.getLogger("worker")
logging.basicConfig(level=logging.INFO)


def log(event: Dict[str, Any]):
    logger.info(json.dumps(event))


# =========================
# TRACE CONTEXT
# =========================

def new_correlation_id() -> str:
    return str(uuid.uuid4())


# =========================
# METRICS (Prometheus-ready placeholder)
# =========================

class Metrics:
    def __init__(self):
        self.processed = 0
        self.failed = 0
        self.retried = 0
        self.dlq = 0

    def inc_processed(self): self.processed += 1
    def inc_failed(self): self.failed += 1
    def inc_retry(self): self.retried += 1
    def inc_dlq(self): self.dlq += 1


metrics = Metrics()


# =========================
# DLQ MANAGER
# =========================

class DLQManager:
    def __init__(self, redis_client):
        self.redis = redis_client

    async def send(self, job: dict, error: str):
        payload = {
            "job": job,
            "error": error,
            "timestamp": time.time()
        }
        await self.redis.rpush(DLQ_NAME, json.dumps(payload))
        metrics.inc_dlq()


# =========================
# RETRY ENGINE
# =========================

class RetryEngine:
    def __init__(self):
        pass

    def should_retry(self, attempt: int) -> bool:
        return attempt < MAX_RETRIES

    def backoff(self, attempt: int):
        delay = min(MAX_BACKOFF, BASE_BACKOFF * (2 ** attempt))
        jitter = random.uniform(0, delay * 0.3)
        return delay + jitter


# =========================
# CIRCUIT BREAKER
# =========================

class CircuitBreaker:
    def __init__(self, threshold=5, cooldown=10):
        self.failures = 0
        self.threshold = threshold
        self.cooldown = cooldown
        self.open_until = 0

    def allow(self) -> bool:
        if time.time() < self.open_until:
            return False
        return True

    def record_failure(self):
        self.failures += 1
        if self.failures >= self.threshold:
            self.open_until = time.time() + self.cooldown
            self.failures = 0

    def record_success(self):
        self.failures = 0


# =========================
# PROCESSOR (BUSINESS LOGIC PLACEHOLDER)
# =========================

async def process_job(job: dict):
    # Simulated processing
    await asyncio.sleep(0.1)

    if job.get("force_fail"):
        raise ValueError("Simulated processing error")

    return True


# =========================
# WORKER CORE
# =========================

class Worker:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.dlq = DLQManager(redis_client)
        self.retry_engine = RetryEngine()
        self.circuit = CircuitBreaker()
        self.running = True

    async def fetch_job(self) -> Optional[dict]:
        raw = await self.redis.lpop(QUEUE_NAME)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            # poison message → DLQ
            await self.dlq.send({"raw": raw}, "invalid_json")
            return None

    async def handle_job(self, job: dict):
        correlation_id = job.get("correlation_id") or new_correlation_id()
        job_id = job.get("job_id", "unknown")

        attempt = job.get("attempt", 0)
        start = time.time()

        if not self.circuit.allow():
            await asyncio.sleep(1)
            return

        try:
            await process_job(job)

            self.circuit.record_success()
            metrics.inc_processed()

            log({
                "correlation_id": correlation_id,
                "job_id": job_id,
                "status": "success",
                "retry_count": attempt,
                "processing_time_ms": int((time.time() - start) * 1000),
                "worker_id": os.getpid(),
                "error_type": None,
                "timestamp": time.time()
            })

        except Exception as e:
            self.circuit.record_failure()
            metrics.inc_failed()

            error_type = type(e).__name__

            log({
                "correlation_id": correlation_id,
                "job_id": job_id,
                "status": "error",
                "retry_count": attempt,
                "processing_time_ms": int((time.time() - start) * 1000),
                "worker_id": os.getpid(),
                "error_type": error_type,
                "timestamp": time.time()
            })

            # retry logic
            if self.retry_engine.should_retry(attempt):
                metrics.inc_retry()
                delay = self.retry_engine.backoff(attempt)

                job["attempt"] = attempt + 1

                await asyncio.sleep(delay)
                await self.redis.rpush(QUEUE_NAME, json.dumps(job))
            else:
                await self.dlq.send(job, str(e))

    async def worker_loop(self):
        while self.running:
            job = await self.fetch_job()

            if not job:
                await asyncio.sleep(0.2)
                continue

            await self.handle_job(job)

    def stop(self):
        self.running = False


# =========================
# WORKER MANAGER
# =========================

class WorkerManager:
    def __init__(self):
        self.redis = redis.Redis(host=REDIS_HOST, decode_responses=True)
        self.worker = Worker(self.redis)
        self.tasks = []

    async def start(self):
        for _ in range(CONCURRENCY):
            task = asyncio.create_task(self.worker.worker_loop())
            self.tasks.append(task)

    async def stop(self):
        self.worker.stop()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.redis.close()


# =========================
# MAIN ENTRYPOINT
# =========================

async def main():
    manager = WorkerManager()

    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(manager.stop()))

    await manager.start()

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
