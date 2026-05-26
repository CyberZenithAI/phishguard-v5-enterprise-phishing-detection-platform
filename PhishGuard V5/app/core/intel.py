from __future__ import annotations

import asyncio
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Literal

from app.core.vt_client import VirusTotalClient
from app.core.otx_client import OTXClient
from app.core.urlhaus import URLHausClient
from app.core.abuseipdb import AbuseIPDBClient

LOGGER = logging.getLogger("threat_intel")


# =========================================================
# 📦 Normalized IOC Model
# =========================================================

@dataclass
class NormalizedIOC:
    ioc: str
    type: str
    sources: List[str] = field(default_factory=list)

    reputation_score: float = 0.0
    confidence: float = 0.0
    classification: str = "unknown"
    malicious: bool = False

    tags: List[str] = field(default_factory=list)
    country: Optional[str] = None
    asn: Optional[str] = None
    last_seen: Optional[str] = None
    threat_types: List[str] = field(default_factory=list)

    raw: Dict[str, Any] = field(default_factory=dict)


# =========================================================
# 🔐 Base Provider Contract (Abstract Layer)
# =========================================================

class IntelProvider(ABC):

    name: str

    @abstractmethod
    async def enrich(self, ioc: str) -> Optional[NormalizedIOC]:
        pass


# =========================================================
# 🧠 VirusTotal Provider
# =========================================================

class VirusTotalProvider(IntelProvider):

    name = "virustotal"

    def __init__(self, client: VirusTotalClient):
        self.client = client

    async def enrich(self, ioc: str) -> Optional[NormalizedIOC]:

        if not self.client.enabled:
            return None

        data = await self.client.lookup_domain(ioc)

        return NormalizedIOC(
            ioc=ioc,
            type="domain",
            sources=[self.name],
            malicious=data.malicious,
            reputation_score=data.reputation or 0,
            confidence=0.85,
            classification="malicious" if data.malicious else "clean",
            tags=data.tags or [],
            raw=data.__dict__,
        )


# =========================================================
# 🌐 AlienVault OTX Provider
# =========================================================

class OTXProvider(IntelProvider):

    name = "otx"

    def __init__(self, client: OTXClient):
        self.client = client

    async def enrich(self, ioc: str) -> Optional[NormalizedIOC]:

        data = await self.client.lookup(ioc)

        if not data:
            return None

        return NormalizedIOC(
            ioc=ioc,
            type="unknown",
            sources=[self.name],
            reputation_score=data.get("pulse_score", 0),
            confidence=data.get("confidence", 0.6),
            classification="suspicious",
            tags=data.get("tags", []),
            threat_types=data.get("malware_families", []),
            raw=data,
        )


# =========================================================
# ⚠️ URLHaus Provider
# =========================================================

class URLHausProvider(IntelProvider):

    name = "urlhaus"

    def __init__(self, client: URLHausClient):
        self.client = client

    async def enrich(self, ioc: str) -> Optional[NormalizedIOC]:

        data = await self.client.lookup(ioc)

        if not data:
            return None

        return NormalizedIOC(
            ioc=ioc,
            type="url",
            sources=[self.name],
            malicious=True,
            reputation_score=0.9,
            confidence=0.9,
            classification="malware",
            tags=["urlhaus_detected"],
            raw=data,
        )


# =========================================================
# 🚨 AbuseIPDB Provider
# =========================================================

class AbuseIPDBProvider(IntelProvider):

    name = "abuseipdb"

    def __init__(self, client: AbuseIPDBClient):
        self.client = client

    async def enrich(self, ioc: str) -> Optional[NormalizedIOC]:

        data = await self.client.lookup_ip(ioc)

        if not data:
            return None

        score = data.get("abuseConfidenceScore", 0)

        return NormalizedIOC(
            ioc=ioc,
            type="ip",
            sources=[self.name],
            reputation_score=score / 100,
            confidence=0.8,
            classification="malicious" if score > 50 else "suspicious",
            country=data.get("countryCode"),
            asn=data.get("asn"),
            last_seen=data.get("lastReportedAt"),
            tags=["abuseipdb"],
            raw=data,
        )


# =========================================================
# ⚡ Threat Intel Aggregator (CORE ENGINE)
# =========================================================

class ThreatIntelAggregator:

    def __init__(
        self,
        vt_client: VirusTotalClient,
        otx_client: OTXClient,
        urlhaus_client: URLHausClient,
        abuseipdb_client: AbuseIPDBClient,
        timeout: float = 8.0,
    ):

        self.providers: List[IntelProvider] = [
            VirusTotalProvider(vt_client),
            OTXProvider(otx_client),
            URLHausProvider(urlhaus_client),
            AbuseIPDBProvider(abuseipdb_client),
        ]

        self.timeout = timeout

    # ---------------------------------------------
    # 🔥 IOC Validation (Security layer)
    # ---------------------------------------------
    def _validate_ioc(self, ioc: str) -> str:
        ioc = ioc.strip()

        if not ioc or len(ioc) > 512:
            raise ValueError("Invalid IOC")

        # Basic SSRF protection
        if "localhost" in ioc or "127.0.0.1" in ioc:
            raise ValueError("Blocked IOC")

        return ioc

    # ---------------------------------------------
    # ⚡ Async provider execution
    # ---------------------------------------------
    async def _run_provider(self, provider: IntelProvider, ioc: str):

        try:
            return await asyncio.wait_for(
                provider.enrich(ioc),
                timeout=self.timeout,
            )
        except Exception as e:
            LOGGER.warning(
                f"[{provider.name}] failed | ioc={ioc} | err={e}"
            )
            return None

    # ---------------------------------------------
    # 🧠 Correlation Engine
    # ---------------------------------------------
    def _correlate(self, results: List[NormalizedIOC]) -> Dict[str, Any]:

        if not results:
            return self._empty(ioc="unknown")

        malicious_votes = sum(1 for r in results if r.malicious)
        total = len(results)

        avg_score = sum(r.reputation_score for r in results) / total
        avg_conf = sum(r.confidence for r in results) / total

        consensus_malicious = malicious_votes >= (total / 2)

        merged_tags = list({t for r in results for t in r.tags})

        return {
            "ioc": results[0].ioc,
            "type": results[0].type,
            "sources": list({s for r in results for s in r.sources}),

            "reputation_score": round(avg_score, 3),
            "confidence": round(avg_conf, 3),

            "classification": (
                "malicious" if consensus_malicious else "suspicious"
            ),

            "malicious": consensus_malicious,

            "tags": merged_tags,

            "country": results[0].country,
            "asn": results[0].asn,
            "last_seen": results[0].last_seen,

            "threat_types": list({t for r in results for t in r.threat_types}),

            "raw": {
                p.sources[0]: p.raw for p in results if p.raw
            }
        }

    def _empty(self, ioc: str) -> Dict[str, Any]:
        return {
            "ioc": ioc,
            "type": "",
            "sources": [],
            "reputation_score": 0,
            "confidence": 0,
            "classification": "unknown",
            "malicious": False,
            "tags": [],
            "country": None,
            "asn": None,
            "last_seen": None,
            "threat_types": [],
            "raw": {},
        }

    # ---------------------------------------------
    # 🚀 Public API
    # ---------------------------------------------
    async def enrich_ioc(self, ioc: str) -> Dict[str, Any]:

        start = time.perf_counter()

        ioc = self._validate_ioc(ioc)

        tasks = [
            self._run_provider(p, ioc)
            for p in self.providers
        ]

        results = await asyncio.gather(*tasks)

        filtered: List[NormalizedIOC] = [
            r for r in results if r is not None
        ]

        correlated = self._correlate(filtered)

        latency = time.perf_counter() - start

        correlated["observability"] = {
            "latency_ms": round(latency * 1000, 2),
            "providers_used": len(self.providers),
            "successful_sources": len(filtered),
        }

        return correlated


# =========================================================
# 🧩 Singleton Engine
# =========================================================

_vt = VirusTotalClient(os.getenv("VT_API_KEY", ""))
_otx = OTXClient(os.getenv("OTX_API_KEY", ""))
_urlhaus = URLHausClient()
_abuse = AbuseIPDBClient(os.getenv("ABUSEIPDB_API_KEY", ""))

intel_engine = ThreatIntelAggregator(
    vt_client=_vt,
    otx_client=_otx,
    urlhaus_client=_urlhaus,
    abuseipdb_client=_abuse,
)


# =========================================================
# 🌍 Public function (FastAPI ready)
# =========================================================

async def enrich(ioc: str) -> Dict[str, Any]:
    return await intel_engine.enrich_ioc(ioc)
