# app/core/vt_client.py

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

import httpx


# =========================
# LOGGER (structured JSON)
# =========================

LOGGER = logging.getLogger("phishguard.vt_client")


def log(event: dict) -> None:
    LOGGER.info(json.dumps(event, ensure_ascii=False))


# =========================
# CONSTANTS
# =========================

VT_API_URL = "https://www.virustotal.com/api/v3"


# =========================
# EXCEPTIONS (Domain Layer)
# =========================

class VTError(Exception): ...
class AuthenticationError(VTError): ...
class RateLimitError(VTError): ...
class NetworkError(VTError): ...
class MalformedIOCError(VTError): ...
class ForbiddenError(VTError): ...


# =========================
# METRICS (lightweight)
# =========================

@dataclass
class Metrics:
    requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    retries: int = 0
    errors: int = 0


METRICS = Metrics()


# =========================
# RESULT MODEL
# =========================

@dataclass(slots=True)
class VTResult:
    source: str
    observable: str
    reputation_score: int = 0
    malicious: bool = False
    confidence: float = 0.0
    detections: int = 0
    classification: str = "unknown"
    cache_status: str = "miss"
    cache_ttl: int = 0
    latency_ms: float = 0.0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ"))


# =========================
# CACHE (Async + TTL per item)
# =========================

class DynamicCache:
    def __init__(self):
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str):
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None

            value, exp = item
            if time.time() > exp:
                del self._store[key]
                return None

            return value

    async def set(self, key: str, value: Any, ttl: int):
        async with self._lock:
            self._store[key] = (value, time.time() + ttl)


CACHE = DynamicCache()


# =========================
# ERROR CLASSIFIER
# =========================

class ErrorClassifier:

    @staticmethod
    def classify(exc: Exception) -> str:

        if isinstance(exc, httpx.TimeoutException):
            return "recoverable"

        if isinstance(exc, httpx.ConnectError):
            return "recoverable"

        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            if status in (401, 403):
                return "non_recoverable"
            if status == 429:
                return "recoverable"
            if 500 <= status < 600:
                return "recoverable"
            return "non_recoverable"

        if isinstance(exc, json.JSONDecodeError):
            return "recoverable"

        if isinstance(exc, (AuthenticationError, MalformedIOCError, ForbiddenError)):
            return "non_recoverable"

        return "recoverable"


# =========================
# RETRY ENGINE
# =========================

class RetryEngine:

    def __init__(self, max_attempts: int = 3):
        self.max_attempts = max_attempts

    async def run(self, func, *args, **kwargs):
        last_exc = None

        for attempt in range(1, self.max_attempts + 1):

            try:
                return await func(*args, **kwargs)

            except Exception as exc:
                last_exc = exc
                METRICS.retries += 1

                classification = ErrorClassifier.classify(exc)

                if classification == "non_recoverable":
                    raise

                delay = (2 ** attempt) + random.uniform(0.1, 0.5)

                log({
                    "event": "retry",
                    "attempt": attempt,
                    "error_type": type(exc).__name__,
                    "delay": delay,
                })

                await asyncio.sleep(delay)

        raise last_exc


# =========================
# VT CLIENT
# =========================

class VirusTotalClient:

    def __init__(self, api_key: str | None):

        self.enabled = bool(api_key and len(api_key.strip()) >= 32)

        if not self.enabled:
            log({"event": "vt_disabled", "reason": "invalid_api_key"})
            return

        self.api_key = api_key.strip()

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            headers={
                "x-apikey": self.api_key,
                "accept": "application/json",
            },
        )

        self.retry_engine = RetryEngine()

    # =========================
    # VALIDATION (SSRF protection)
    # =========================

    def _validate_ip(self, ip: str):
        try:
            ipaddress.ip_address(ip)
        except Exception:
            raise MalformedIOCError("invalid IP")

    def _validate_domain(self, domain: str):
        if len(domain) < 3 or " " in domain:
            raise MalformedIOCError("invalid domain")

    def _validate_url(self, url: str):
        if not url.startswith(("http://", "https://")):
            raise MalformedIOCError("invalid URL (SSRF protection)")

    # =========================
    # CACHE TTL STRATEGY
    # =========================

    def _compute_ttl(self, detections: int, reputation: int) -> int:

        if detections >= 5:
            return 60  # critical → fresh
        if detections >= 1:
            return 300  # suspicious
        if reputation > 50:
            return 3600  # benign stable
        return 900  # default

    # =========================
    # CORE REQUEST
    # =========================

    async def _request(self, url: str) -> dict:

        METRICS.requests += 1
        start = time.time()

        correlation_id = str(uuid.uuid4())

        try:
            resp = await self.client.get(url)
            resp.raise_for_status()
            data = resp.json()

            log({
                "event": "vt_request",
                "correlation_id": correlation_id,
                "status": resp.status_code,
                "latency_ms": (time.time() - start) * 1000,
            })

            return data

        except httpx.HTTPStatusError as e:
            METRICS.errors += 1
            raise

        except httpx.TimeoutException as e:
            METRICS.errors += 1
            raise NetworkError(str(e))

        except httpx.ConnectError as e:
            METRICS.errors += 1
            raise NetworkError(str(e))

        except json.JSONDecodeError as e:
            METRICS.errors += 1
            raise

    # =========================
    # PARSE RESPONSE
    # =========================

    def _parse(self, data: dict, observable: str) -> VTResult:

        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        detections = stats.get("malicious", 0)
        reputation = attr.get("reputation", 0)

        return VTResult(
            source="virustotal",
            observable=observable,
            reputation_score=reputation,
            malicious=detections > 0,
            confidence=min(1.0, detections / 10),
            detections=detections,
            classification="malicious" if detections > 0 else "clean",
        )

    # =========================
    # LOOKUP METHODS
    # =========================

    async def lookup_ip(self, ip: str) -> VTResult:

        self._validate_ip(ip)

        cache_key = f"ip:{ip}"
        cached = await CACHE.get(cache_key)

        if cached:
            METRICS.cache_hits += 1
            cached.cache_status = "hit"
            return cached

        METRICS.cache_misses += 1

        url = f"{VT_API_URL}/ip_addresses/{ip}"

        data = await self.retry_engine.run(self._request, url)

        result = self._parse(data, ip)

        ttl = self._compute_ttl(result.detections, result.reputation_score)
        result.cache_ttl = ttl

        await CACHE.set(cache_key, result, ttl)

        result.cache_status = "miss"
        return result

    async def lookup_domain(self, domain: str) -> VTResult:

        self._validate_domain(domain)

        cache_key = f"domain:{domain}"
        cached = await CACHE.get(cache_key)

        if cached:
            METRICS.cache_hits += 1
            cached.cache_status = "hit"
            return cached

        url = f"{VT_API_URL}/domains/{quote(domain)}"

        data = await self.retry_engine.run(self._request, url)

        result = self._parse(data, domain)

        ttl = self._compute_ttl(result.detections, result.reputation_score)
        await CACHE.set(cache_key, result, ttl)

        return result

    async def lookup_url(self, url: str) -> VTResult:

        self._validate_url(url)

        cache_key = f"url:{url}"
        cached = await CACHE.get(cache_key)

        if cached:
            METRICS.cache_hits += 1
            cached.cache_status = "hit"
            return cached

        encoded = quote(url, safe="")
        full_url = f"{VT_API_URL}/urls/{encoded}"

        data = await self.retry_engine.run(self._request, full_url)

        result = self._parse(data, url)

        ttl = self._compute_ttl(result.detections, result.reputation_score)
        await CACHE.set(cache_key, result, ttl)

        return result

    # =========================
    # CLOSE
    # =========================

    async def close(self):
        if self.enabled:
            await self.client.aclose()
