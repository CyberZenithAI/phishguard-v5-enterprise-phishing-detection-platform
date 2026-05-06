import os

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
DNS_TIMEOUT = 2
MAX_CONCURRENCY = 50
CACHE_TTL = 300