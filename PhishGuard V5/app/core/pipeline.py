from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, List
from datetime import datetime, timezone
import asyncio
import os
import re
import socket
import uuid
import math
import time

import httpx


# =========================
# 🔐 CONFIGURATION (ENV SAFE)
# =========================

VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"


# =========================
# ⚡ UTILS: TIME / CACHE
# =========================

class TTLCache:
    def __init__(self, ttl_seconds: int = 300):
        self.ttl = ttl_seconds
        self.store: Dict[str, Any] = {}

    def get(self, key: str):
        value = self.store.get(key)
        if not value:
            return None
        v, ts = value
        if time.time() - ts > self.ttl:
            del self.store[key]
            return None
        return v

    def set(self, key: str, value: Any):
        self.store[key] = (value, time.time())


cache = TTLCache()


# =========================
# ⚡ RATE LIMITER (token bucket)
# =========================

class RateLimiter:
    def __init__(self, rate: int = 10, per: float = 1.0):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.time()

    async def acquire(self):
        now = time.time()
        time_passed = now - self.last_check
        self.last_check = now
        self.allowance += time_passed * (self.rate / self.per)

        if self.allowance > self.rate:
            self.allowance = self.rate

        if self.allowance < 1.0:
            await asyncio.sleep(0.2)
            return await self.acquire()

        self.allowance -= 1.0


rate_limiter = RateLimiter()


# =========================
# ⚡ CIRCUIT BREAKER
# =========================

class CircuitBreaker:
    def __init__(self, fail_threshold: int = 3, reset_timeout: int = 30):
        self.failures = 0
        self.fail_threshold = fail_threshold
        self.reset_timeout = reset_timeout
        self.open_until = 0

    def allow(self) -> bool:
        return time.time() > self.open_until

    def success(self):
        self.failures = 0

    def fail(self):
        self.failures += 1
        if self.failures >= self.fail_threshold:
            self.open_until = time.time() + self.reset_timeout


breaker = CircuitBreaker()


# =========================
# 🧠 IOC VALIDATION
# =========================

def is_valid_url(url: str) -> bool:
    return bool(re.match(r"^https?://[^\s]+$", url))


def normalize_ioc(url: str) -> str:
    return url.strip().lower()


# =========================
# 🌐 DNS INTELLIGENCE
# =========================

async def dns_enrichment(hostname: str) -> Dict[str, Any]:
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.getaddrinfo(hostname, None)
        resolved_ips = list({i[4][0] for i in ip})

        suspicious_tld = hostname.split(".")[-1] in {
            "zip", "mov", "top", "xyz", "click"
        }

        return {
            "resolved_ips": resolved_ips,
            "suspicious_tld": suspicious_tld,
            "dns_reputation_score": 0.2 if suspicious_tld else 0.0
        }
    except Exception:
        return {
            "resolved_ips": [],
            "suspicious_tld": False,
            "dns_reputation_score": 0.5
        }


# =========================
# 🌐 THREAT INTEL CLIENTS
# =========================

async def vt_lookup(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {"score": 0.0, "source": "virustotal", "disabled": True}

    cache_key = f"vt:{url}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    headers = {"x-apikey": VT_API_KEY}
    encoded = httpx.URL(url).raw_path.decode()

    try:
        await rate_limiter.acquire()
        resp = await client.get(f"{VT_BASE}/urls", headers=headers, timeout=8)

        data = resp.json()
        result = {
            "malicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
            "score": min(1.0, data.get("data", {}).get("attributes", {}).get("reputation", 0) / 100),
            "source": "virustotal"
        }

        cache.set(cache_key, result)
        return result

    except Exception:
        breaker.fail()
        return {"score": 0.0, "source": "virustotal", "error": True}


async def otx_lookup(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    if not OTX_API_KEY:
        return {"score": 0.0, "source": "otx", "disabled": True}

    cache_key = f"otx:{url}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        await rate_limiter.acquire()
        resp = await client.get(f"{OTX_BASE}/indicators/url/{url}", headers=headers, timeout=8)
        data = resp.json()

        pulses = len(data.get("pulse_info", {}).get("pulses", []))

        result = {
            "pulse_count": pulses,
            "score": min(1.0, pulses / 10),
            "source": "otx"
        }

        cache.set(cache_key, result)
        return result

    except Exception:
        breaker.fail()
        return {"score": 0.0, "source": "otx", "error": True}


async def urlhaus_lookup(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    try:
        await rate_limiter.acquire()
        resp = await client.post(URLHAUS_API, data={"url": url}, timeout=8)
        data = resp.json()

        return {
            "is_malicious": data.get("query_status") == "ok",
            "score": 1.0 if data.get("query_status") == "ok" else 0.0,
            "source": "urlhaus"
        }

    except Exception:
        return {"score": 0.0, "source": "urlhaus", "error": True}


# =========================
# 🧠 REPUTATION ENGINE
# =========================

def compute_reputation(signals: List[Dict[str, Any]], dns: Dict[str, Any]) -> Dict[str, Any]:
    vt = sum(s.get("score", 0) for s in signals if s["source"] == "virustotal")
    otx = sum(s.get("score", 0) for s in signals if s["source"] == "otx")
    urlhaus = sum(s.get("score", 0) for s in signals if s["source"] == "urlhaus")

    dns_score = dns.get("dns_reputation_score", 0)

    raw_score = (vt * 0.45) + (otx * 0.25) + (urlhaus * 0.2) + (dns_score * 0.1)

    score = min(100, math.floor(raw_score * 100))

    if score <= 25:
        label = "benign"
    elif score <= 50:
        label = "suspicious"
    elif score <= 75:
        label = "malicious"
    else:
        label = "critical"

    return {
        "score": score,
        "label": label,
        "confidence": round(1 - abs(0.5 - raw_score), 2)
    }


# =========================
# 🚀 PIPELINE CORE
# =========================

@dataclass
class PipelineResult(Dict[str, Any]):
    pass


async def analyze(url: str) -> PipelineResult:
    correlation_id = str(uuid.uuid4())
    start = datetime.now(timezone.utc)

    if not is_valid_url(url):
        return PipelineResult({
            "url": url,
            "error": "invalid_url",
            "correlation_id": correlation_id
        })

    url = normalize_ioc(url)
    hostname = url.split("/")[2]

    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=20)) as client:

        tasks = await asyncio.gather(
            vt_lookup(client, url),
            otx_lookup(client, url),
            urlhaus_lookup(client, url),
            dns_enrichment(hostname),
            return_exceptions=True
        )

    vt, otx, urlhaus, dns = tasks

    signals = [s for s in [vt, otx, urlhaus] if isinstance(s, dict)]

    reputation = compute_reputation(signals, dns if isinstance(dns, dict) else {})

    latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    return PipelineResult({
        "url": url,
        "is_phishing": reputation["label"] in ["malicious", "critical"],
        "score": reputation["score"],
        "risk_level": reputation["label"],
        "confidence": reputation["confidence"],
        "timestamp": start.isoformat(),
        "engine": "phishguard-ti-v1",
        "correlation_id": correlation_id,
        "pipeline_stage": "complete",
        "latency_ms": round(latency, 2),
        "signals": signals,
        "dns": dns,
        "reputation": reputation
    })
