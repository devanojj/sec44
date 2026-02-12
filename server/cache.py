from __future__ import annotations

import json
import logging
from typing import Any

import redis

logger = logging.getLogger("endpoint_server.cache")


class RedisCache:
    def __init__(self, redis_url: str) -> None:
        self.client = redis.Redis.from_url(redis_url, decode_responses=True)

    def ping(self) -> None:
        self.client.ping()

    def get_json(self, key: str) -> Any | None:
        try:
            value = self.client.get(key)
        except redis.RedisError:
            return None
        if value is None:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None

    def set_json(self, key: str, value: Any, ttl_seconds: int) -> None:
        payload = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        try:
            self.client.set(name=key, value=payload, ex=max(1, ttl_seconds))
        except redis.RedisError:
            return

    def delete_prefix(self, prefix: str) -> None:
        try:
            keys = self.client.keys(f"{prefix}*")
            if keys:
                self.client.delete(*keys)
        except redis.RedisError:
            logger.exception("failed cache deletion for prefix")


class RedisRateLimiter:
    def __init__(self, redis_url: str, fail_closed: bool = True) -> None:
        self.client = redis.Redis.from_url(redis_url, decode_responses=True)
        self.fail_closed = fail_closed
        self._local_counts: dict[str, tuple[int, float]] = {}

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        bucket = f"ratelimit:{key}"
        try:
            count = self.client.incr(bucket)
            if count == 1:
                self.client.expire(bucket, max(1, window_seconds))
            return int(count) <= max(1, limit)
        except redis.RedisError:
            if self.fail_closed:
                return False
            now = 0.0
            try:
                import time

                now = time.time()
            except Exception:
                now = 0.0
            count, reset_at = self._local_counts.get(bucket, (0, now + window_seconds))
            if now >= reset_at:
                count = 0
                reset_at = now + window_seconds
            count += 1
            self._local_counts[bucket] = (count, reset_at)
            return count <= max(1, limit)
