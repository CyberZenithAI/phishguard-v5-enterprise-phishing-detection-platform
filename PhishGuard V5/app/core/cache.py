import asyncio
import json
import time
import hashlib
import logging
from typing import Any, Optional, Dict

import redis.asyncio as redis

from app.core.config import (
    REDIS_HOST,
    REDIS_PORT,
    CACHE_TTL,
    CACHE_NAMESPACE,
)

logger = logging.getLogger("cache")


# ---------------------------
# 🔐 Key Security Layer
# ---------------------------
def _normalize_key(key: str) -> str:
    """Prevents cache poisoning + ensures deterministic keys."""
    safe = f"{CACHE_NAMESPACE}:{key}"
    return hashlib.sha256(safe.encode()).hexdigest()


# ---------------------------
# 🧠 In-Memory Fallback Cache
# ---------------------------
class _MemoryCache:
    def __init__(self):
        self._store: Dict[str, tuple] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str):
        async with self._lock:
            data = self._store.get(key)
            if not data:
                return None

            value, expires_at = data
            if time.time() > expires_at:
                del self._store[key]
                return None

            return value

    async def set(self, key: str, value: Any, ttl: int):
        async with self._lock:
            self._store[key] = (value, time.time() + ttl)

    async def delete(self, key: str):
        async with self._lock:
            self._store.pop(key, None)

    async def exists(self, key: str) -> bool:
        async with self._lock:
            return key in self._store


# ---------------------------
# 🚀 Cache Manager (Singleton)
# ---------------------------
class CacheManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return

        self._initialized = True
        self.redis: Optional[redis.Redis] = None
        self.memory_cache = _MemoryCache()
        self._redis_healthy = False

    # -----------------------
    # 🔌 Initialization
    # -----------------------
    async def connect(self):
        try:
            self.redis = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
                retry_on_timeout=True,
                health_check_interval=30,
            )

            await self.redis.ping()
            self._redis_healthy = True

            logger.info("Redis cache connected successfully")

        except Exception as e:
            self._redis_healthy = False
            logger.warning(f"Redis unavailable, fallback enabled: {e}")

    # -----------------------
    # 🧠 GET
    # -----------------------
    async def get(self, key: str) -> Any:
        norm_key = _normalize_key(key)

        try:
            if self._redis_healthy and self.redis:
                val = await self.redis.get(norm_key)
                if val is not None:
                    logger.debug("CACHE HIT (redis)")
                    return json.loads(val)

            # fallback
            val = await self.memory_cache.get(norm_key)
            if val is not None:
                logger.debug("CACHE HIT (memory)")
                return val

        except Exception as e:
            logger.error(f"Cache GET error: {e}")
            return await self.memory_cache.get(norm_key)

        return None

    # -----------------------
    # 🧠 SET
    # -----------------------
    async def set(self, key: str, value: Any, ttl: int = CACHE_TTL):
        norm_key = _normalize_key(key)

        # 🚨 Security: prevent caching sensitive objects
        if isinstance(value, dict):
            forbidden = {"password", "token", "jwt", "secret"}
            if any(k.lower() in forbidden for k in value.keys()):
                logger.warning("Attempt to cache sensitive data blocked")
                return

        try:
            payload = json.dumps(value)

            if self._redis_healthy and self.redis:
                await self.redis.setex(norm_key, ttl, payload)
                logger.debug("CACHE SET (redis)")
                return

        except Exception as e:
            logger.error(f"Redis SET failed: {e}")

        # fallback memory
        await self.memory_cache.set(norm_key, value, ttl)
        logger.debug("CACHE SET (memory fallback)")

    # -----------------------
    # 🗑 DELETE
    # -----------------------
    async def delete(self, key: str):
        norm_key = _normalize_key(key)

        try:
            if self.redis:
                await self.redis.delete(norm_key)
        except Exception:
            pass

        await self.memory_cache.delete(norm_key)

    # -----------------------
    # 🔍 EXISTS
    # -----------------------
    async def exists(self, key: str) -> bool:
        norm_key = _normalize_key(key)

        try:
            if self.redis:
                if await self.redis.exists(norm_key):
                    return True
        except Exception:
            pass

        return await self.memory_cache.exists(norm_key)

    # -----------------------
    # 🧹 PATTERN INVALIDATION
    # -----------------------
    async def invalidate_pattern(self, pattern: str):
        safe_pattern = _normalize_key(pattern)[:20] + "*"

        try:
            if self.redis:
                keys = await self.redis.keys(safe_pattern)
                if keys:
                    await self.redis.delete(*keys)
        except Exception as e:
            logger.error(f"Pattern invalidation failed: {e}")

    # -----------------------
    # ❤️ HEALTH CHECK
    # -----------------------
    async def health_check(self) -> Dict[str, Any]:
        status = {
            "redis": False,
            "fallback_memory": True,
        }

        try:
            if self.redis:
                await self.redis.ping()
                status["redis"] = True
                self._redis_healthy = True
        except Exception:
            self._redis_healthy = False

        return status

    # -----------------------
    # 🔄 GRACEFUL FALLBACK RECOVERY
    # -----------------------
    async def graceful_fallback(self):
        try:
            await self.connect()
        except Exception as e:
            logger.error(f"Fallback recovery failed: {e}")
            self._redis_healthy = False
