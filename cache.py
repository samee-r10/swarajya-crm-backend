import os
import json
import logging
from functools import wraps
from flask import request, session

logger = logging.getLogger("crm.cache")

_redis_client = None
_redis_checked = False
_redis_enabled = True

def get_redis_client():
    """
    Returns the Redis client or None if Redis is disabled or unreachable.
    Fails open gracefully so the application never breaks if Redis is down.
    """
    global _redis_client, _redis_checked, _redis_enabled

    if not _redis_enabled:
        return None

    if _redis_client is not None:
        return _redis_client

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    try:
        import redis
        client = redis.from_url(
            redis_url,
            socket_timeout=0.8,
            socket_connect_timeout=0.8,
            decode_responses=True
        )
        client.ping()
        _redis_client = client
        if not _redis_checked:
            logger.info("✓ Redis cache connected successfully: %s", redis_url)
            _redis_checked = True
        return _redis_client
    except Exception as e:
        if not _redis_checked:
            logger.warning("Redis is unavailable (%s). Falling back to non-cached execution.", e)
            _redis_checked = True
        return None

def is_redis_available():
    return get_redis_client() is not None

def cache_get(key: str):
    """Safely get and deserialize a JSON object from Redis."""
    try:
        client = get_redis_client()
        if not client:
            return None
        raw = client.get(key)
        if raw is not None:
            return json.loads(raw)
    except Exception as e:
        logger.debug("Redis cache_get error for %s: %s", key, e)
    return None

def cache_set(key: str, value, ttl: int = 300):
    """Safely serialize and set a JSON object in Redis with a TTL (seconds)."""
    try:
        client = get_redis_client()
        if not client:
            return False
        serialized = json.dumps(value, default=str)
        client.setex(key, ttl, serialized)
        return True
    except Exception as e:
        logger.debug("Redis cache_set error for %s: %s", key, e)
    return False

def cache_delete(key: str):
    """Safely delete a key from Redis."""
    try:
        client = get_redis_client()
        if client:
            client.delete(key)
    except Exception as e:
        logger.debug("Redis cache_delete error: %s", e)

def cache_delete_pattern(pattern: str):
    """
    Safely delete all keys matching a pattern using non-blocking SCAN.
    Example: cache_delete_pattern("tasks:*")
    """
    try:
        client = get_redis_client()
        if not client:
            return
        cursor = 0
        while True:
            cursor, keys = client.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                client.delete(*keys)
            if cursor == 0:
                break
    except Exception as e:
        logger.debug("Redis cache_delete_pattern error for pattern %s: %s", pattern, e)

def invalidate_cache(scope: str):
    """Invalidate a family of caches (e.g. 'tasks', 'dashboard', 'settings', 'options')."""
    cache_delete_pattern(f"crm:{scope}:*")

def cache_endpoint(prefix: str, ttl: int = 180, user_scoped: bool = False):
    """
    Flask decorator to cache JSON responses.
    Automatically respects query parameters and user context if user_scoped=True.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.method != "GET":
                return f(*args, **kwargs)

            # Build unique cache key
            user_part = f":user:{session.get('user_id', 'anon')}" if user_scoped else ""
            query_part = f":{request.query_string.decode('utf-8')}" if request.query_string else ""
            cache_key = f"crm:{prefix}{user_part}{query_part}"

            # Check cache
            cached = cache_get(cache_key)
            if cached is not None:
                from flask import jsonify, make_response
                resp = make_response(jsonify(cached))
                resp.headers["X-Cache"] = "HIT"
                return resp

            # Execute endpoint handler
            res = f(*args, **kwargs)

            # If response is successful JSON, cache it
            try:
                # Handle Response or (Response, status) or dict
                from flask import Response
                if isinstance(res, tuple):
                    res_obj, status = res[0], res[1]
                else:
                    res_obj, status = res, 200

                if status == 200 and isinstance(res_obj, Response) and res_obj.is_json:
                    data = res_obj.get_json()
                    cache_set(cache_key, data, ttl=ttl)
                    res_obj.headers["X-Cache"] = "MISS"
            except Exception as e:
                logger.debug("Failed to store endpoint in cache: %s", e)

            return res
        return wrapper
    return decorator

