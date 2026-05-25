# app/core/otx_client.py

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx
from cachetools import TTLCache
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

LOGGER = logging.getLogger(__name__)

OTX_API = "https://otx.alienvault.com/api/v1"
CACHE = TTLCache(maxsize=1024, ttl=1800)


@dataclass(slots=True)
class OTXResult:
    source: str
    observable: str
    pulse_count: int
    malware_families: list[str]
    threat_actors: list[str]
    confidence: int
    raw: dict


class OTXClient:

    def __init__(self, api_key: str) -> None:

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            verify=True,
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=10,
            ),
            headers={
                "X-OTX-API-KEY": api_key,
                "accept": "application/json",
            },
        )

    async def close(self) -> None:
        await self.client.aclose()

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    async def lookup(self, indicator_type: str, observable: str) -> OTXResult:

        cache_key = f"otx_{indicator_type}_{observable}"

        if cache_key in CACHE:
            return CACHE[cache_key]

        url = (
            f"{OTX_API}/indicators/{indicator_type}/{observable}/general"
        )

        response = await self.client.get(url)

        if response.status_code == 429:
            await asyncio.sleep(10)
            raise httpx.HTTPError("rate_limited")

        response.raise_for_status()

        data = response.json()

        pulses = data.get("pulse_info", {}).get("pulses", [])

        malware_families = sorted(
            {
                pulse.get("malware_family")
                for pulse in pulses
                if pulse.get("malware_family")
            }
        )

        threat_actors = sorted(
            {
                pulse.get("adversary")
                for pulse in pulses
                if pulse.get("adversary")
            }
        )

        result = OTXResult(
            source="otx",
            observable=observable,
            pulse_count=len(pulses),
            malware_families=malware_families,
            threat_actors=threat_actors,
            confidence=min(len(pulses) * 10, 100),
            raw=data,
        )

        CACHE[cache_key] = result

        return result
