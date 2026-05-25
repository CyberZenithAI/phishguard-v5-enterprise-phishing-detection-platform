# app/core/vt_client.py

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from cachetools import TTLCache
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

LOGGER = logging.getLogger(__name__)

VT_API_URL = "https://www.virustotal.com/api/v3"
CACHE = TTLCache(maxsize=2048, ttl=1800)


@dataclass(slots=True)
class VTResult:
    source: str
    observable: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    reputation: int = 0
    tags: list[str] = None
    raw: dict = None


class VirusTotalClient:

    def __init__(self, api_key: str | None = None) -> None:

        self.enabled = False
        self.client = None

        if not api_key:
            LOGGER.warning("VirusTotal disabled: missing API key")
            return

        api_key = api_key.strip()

        if len(api_key) < 32:
            LOGGER.warning("VirusTotal disabled: invalid API key format")
            return

        self.enabled = True

        self.headers = {
            "x-apikey": api_key,
            "accept": "application/json",
        }

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            verify=True,
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            ),
            headers=self.headers,
        )

        LOGGER.info("VirusTotal client initialized successfully")

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()

    @staticmethod
    def sanitize_ioc(value: str) -> str:
        return value.strip().lower()

    async def _safe_disabled_result(self, observable: str) -> VTResult:
        return VTResult(
            source="virustotal",
            observable=observable,
            malicious=0,
            suspicious=0,
            harmless=0,
            reputation=0,
            tags=[],
            raw={"status": "disabled"},
        )

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    async def _request(self, endpoint: str) -> dict:

        if not self.enabled:
            return {"data": {"attributes": {}}}

        try:

            response = await self.client.get(endpoint)

            if response.status_code == 429:
                LOGGER.warning("VirusTotal rate limited")
                await asyncio.sleep(15)
                raise httpx.HTTPError("rate_limited")

            if response.status_code == 401:
                LOGGER.error("VirusTotal unauthorized API key")
                return {"data": {"attributes": {}}}

            response.raise_for_status()

            return response.json()

        except Exception as e:
            LOGGER.error(f"VirusTotal request failed: {e}")

            return {"data": {"attributes": {}}}

    async def lookup_ip(self, ip: str) -> VTResult:

        if not self.enabled:
            return await self._safe_disabled_result(ip)

        ipaddress.ip_address(ip)

        cache_key = f"vt_ip_{ip}"

        if cache_key in CACHE:
            return CACHE[cache_key]

        endpoint = f"{VT_API_URL}/ip_addresses/{ip}"

        data = await self._request(endpoint)

        attributes = data.get("data", {}).get("attributes", {})

        result = VTResult(
            source="virustotal",
            observable=ip,
            malicious=attributes.get("last_analysis_stats", {}).get("malicious", 0),
            suspicious=attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            harmless=attributes.get("last_analysis_stats", {}).get("harmless", 0),
            reputation=attributes.get("reputation", 0),
            tags=attributes.get("tags", []),
            raw=data,
        )

        CACHE[cache_key] = result

        return result

    async def lookup_domain(self, domain: str) -> VTResult:

        if not self.enabled:
            return await self._safe_disabled_result(domain)

        domain = self.sanitize_ioc(domain)

        cache_key = f"vt_domain_{domain}"

        if cache_key in CACHE:
            return CACHE[cache_key]

        endpoint = f"{VT_API_URL}/domains/{quote(domain)}"

        data = await self._request(endpoint)

        attributes = data.get("data", {}).get("attributes", {})

        result = VTResult(
            source="virustotal",
            observable=domain,
            malicious=attributes.get("last_analysis_stats", {}).get("malicious", 0),
            suspicious=attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            harmless=attributes.get("last_analysis_stats", {}).get("harmless", 0),
            reputation=attributes.get("reputation", 0),
            tags=attributes.get("tags", []),
            raw=data,
        )

        CACHE[cache_key] = result

        return result

    async def lookup_url(self, url: str) -> VTResult:

        if not self.enabled:
            return await self._safe_disabled_result(url)

        cache_key = f"vt_url_{url}"

        if cache_key in CACHE:
            return CACHE[cache_key]

        encoded = quote(url, safe="")

        endpoint = f"{VT_API_URL}/urls/{encoded}"

        data = await self._request(endpoint)

        attributes = data.get("data", {}).get("attributes", {})

        result = VTResult(
            source="virustotal",
            observable=url,
            malicious=attributes.get("last_analysis_stats", {}).get("malicious", 0),
            suspicious=attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            harmless=attributes.get("last_analysis_stats", {}).get("harmless", 0),
            reputation=attributes.get("reputation", 0),
            tags=attributes.get("tags", []),
            raw=data,
        )

        CACHE[cache_key] = result

        return result
