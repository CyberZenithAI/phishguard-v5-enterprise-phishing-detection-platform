import redis
import json
from app.core.config import REDIS_HOST, CACHE_TTL

r = redis.Redis(host=REDIS_HOST, decode_responses=True)

def get(key):
    val = r.get(key)
    return json.loads(val) if val else None

def set(key, value):
    r.setex(key, CACHE_TTL, json.dumps(value))