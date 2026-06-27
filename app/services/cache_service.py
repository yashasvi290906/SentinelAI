"""Redis caching layer for SentinelAI. Falls back to in-memory if Redis unavailable."""
import json
import time
import os
from typing import Any, Optional

_redis_client = None
_memory_cache: dict[str, tuple[Any, float]] = {}
MEMORY_MAX = 1000
MEMORY_TTL = 300

# Flag for health checks
redis_enabled: bool = bool(os.environ.get("REDIS_URL", ""))


def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis
        url = os.environ.get("REDIS_URL", "")
        if not url:
            _redis_client = False
            return None
        _redis_client = redis.from_url(url, decode_responses=True, socket_timeout=3)
        _redis_client.ping()
        return _redis_client
    except Exception:
        _redis_client = False  # sentinel: Redis unavailable
        return None


def cache_get(key: str) -> Optional[Any]:
    r = _get_redis()
    if r and r is not False:
        try:
            val = r.get(f"sentinel:{key}")
            if val:
                return json.loads(val)
        except Exception:
            pass
        return None
    # Fallback to memory
    entry = _memory_cache.get(key)
    if entry and time.time() - entry[1] < MEMORY_TTL:
        return entry[0]
    return None


def cache_set(key: str, value: Any, ttl: int = 300):
    r = _get_redis()
    if r and r is not False:
        try:
            r.setex(f"sentinel:{key}", ttl, json.dumps(value, default=str))
        except Exception:
            pass
        return
    # Memory fallback
    if len(_memory_cache) >= MEMORY_MAX:
        oldest = min(_memory_cache, key=lambda k: _memory_cache[k][1])
        del _memory_cache[oldest]
    _memory_cache[key] = (value, time.time())


def cache_delete(pattern: str):
    r = _get_redis()
    if r and r is not False:
        try:
            keys = r.keys(f"sentinel:{pattern}*")
            if keys:
                r.delete(*keys)
        except Exception:
            pass
    # Memory fallback
    to_delete = [k for k in _memory_cache if k.startswith(pattern)]
    for k in to_delete:
        del _memory_cache[k]


def cache_stats() -> dict:
    r = _get_redis()
    if r and r is not False:
        try:
            keys = r.keys("sentinel:*")
            return {"backend": "redis", "keys": len(keys)}
        except Exception:
            pass
    return {"backend": "memory", "keys": len(_memory_cache)}
