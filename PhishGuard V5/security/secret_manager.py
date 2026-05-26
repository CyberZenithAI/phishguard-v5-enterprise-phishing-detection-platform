import os
import asyncio
import time
from dataclasses import dataclass
from typing import Any, Optional, Dict


class SecretNotFoundError(Exception):
    pass


@dataclass
class CachedSecret:
    value: Any
    expires_at: float


class SecretManager:
    """
    Secure lazy-loading secret manager with:
    - Vault / AWS / K8s abstraction
    - TTL cache
    - Zero logging of secrets
    - Fail-secure behavior
    """

    def __init__(self, ttl: int = 300):
        self._cache: Dict[str, CachedSecret] = {}
        self._ttl = ttl

    async def get_secret(self, key: str, loader) -> Any:
        now = time.time()

        # Cache hit (secure in-memory)
        if key in self._cache:
            cached = self._cache[key]
            if cached.expires_at > now:
                return cached.value

        # Lazy load from provider
        value = await loader()

        if not value:
            raise SecretNotFoundError(f"Secret missing: {key}")

        self._cache[key] = CachedSecret(
            value=value,
            expires_at=now + self._ttl
        )

        return value
