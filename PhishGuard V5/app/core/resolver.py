import dns.asyncresolver
import asyncio
from app.core.cache import get, set
from app.core.config import DNS_TIMEOUT, MAX_CONCURRENCY

resolver = dns.asyncresolver.Resolver()
resolver.lifetime = DNS_TIMEOUT
sem = asyncio.Semaphore(MAX_CONCURRENCY)

async def resolve(domain):
    cached = get(domain)
    if cached:
        return cached

    async with sem:
        try:
            a = await resolver.resolve(domain, "A")
            mx = await resolver.resolve(domain, "MX")

            result = {
                "domain": domain,
                "active": True,
                "a": [r.to_text() for r in a],
                "mx": [r.exchange.to_text() for r in mx]
            }
        except Exception:
            result = {
                "domain": domain,
                "active": False,
                "a": [],
                "mx": []
            }

        set(domain, result)
        return result
