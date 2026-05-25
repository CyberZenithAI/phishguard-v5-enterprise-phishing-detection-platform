# app/core/urlhaus.py

from __future__ import annotations

from dataclasses import dataclass

import httpx
from cachetools import TTLCache
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

CACHE = TTLCache(maxsize=1024, ttl=1800)


@dataclass(slots=True)
class URLHausResult:
    observable: str
    status: str
    malware_family: str | None
    tags: list[str]
    payloads: list[dict]
    malicious: bool
    raw: dict


class URLHausClient:

    def __init__(self) -> None:

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            verify=True,
        )

    async def close(self) -> None:
        await self.client.aclose()

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    async def lookup(self, url: str) -> URLHausResult:

        cache_key = f"urlhaus_{url}"

        if cache_key in CACHE:
            return CACHE[cache_key]

        response = await self.client.post(
            URLHAUS_API,
            data={"url": url},
        )

        response.raise_for_status()

        data = response.json()

        result = URLHausResult(
            observable=url,
            status=data.get("query_status", "unknown"),
            malware_family=data.get("signature"),
            tags=data.get("tags", []),
            payloads=data.get("payloads", []),
            malicious=data.get("url_status") == "online",
            raw=data,
        )

        CACHE[cache_key] = result

        return result
