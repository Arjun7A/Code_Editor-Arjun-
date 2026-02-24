"""Optional Redis-backed cache service used by API read endpoints."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

try:
    import redis
except Exception:  # pragma: no cover - exercised only when redis isn't installed
    redis = None


class CacheService:
    """Thin Redis wrapper with graceful fallback when Redis is unavailable."""

    def __init__(self) -> None:
        self._client: Any = None

    @property
    def enabled(self) -> bool:
        return bool(settings.REDIS_ENABLED)

    def connect(self) -> bool:
        """Connect to Redis once at startup."""
        if not self.enabled:
            logger.info("Redis cache disabled by configuration.")
            return False
        if redis is None:
            logger.warning("redis package not installed; cache disabled.")
            return False
        if self._client is not None:
            return True

        try:
            self._client = redis.Redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=1.5,
                socket_timeout=1.5,
            )
            self._client.ping()
            logger.info("Redis cache connected: %s", settings.REDIS_URL)
            return True
        except Exception as exc:
            logger.warning("Redis unavailable (%s); cache disabled.", exc)
            self._client = None
            return False

    def close(self) -> None:
        if self._client is None:
            return
        try:
            self._client.close()
        except Exception:
            pass
        finally:
            self._client = None

    def _is_ready(self) -> bool:
        return self._client is not None

    def get_json(self, key: str) -> Any | None:
        if not self._is_ready():
            return None
        try:
            raw = self._client.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:
            logger.debug("Redis get failed for %s: %s", key, exc)
            return None

    def set_json(self, key: str, value: Any, ttl_seconds: int) -> None:
        if not self._is_ready():
            return
        try:
            payload = json.dumps(value, default=str)
            ttl = max(1, int(ttl_seconds))
            self._client.setex(key, ttl, payload)
        except Exception as exc:
            logger.debug("Redis set failed for %s: %s", key, exc)

    def delete(self, key: str) -> None:
        if not self._is_ready():
            return
        try:
            self._client.delete(key)
        except Exception as exc:
            logger.debug("Redis delete failed for %s: %s", key, exc)

    def delete_prefix(self, prefix: str) -> None:
        if not self._is_ready():
            return
        try:
            keys = list(self._client.scan_iter(match=f"{prefix}*"))
            if keys:
                self._client.delete(*keys)
        except Exception as exc:
            logger.debug("Redis prefix delete failed for %s: %s", prefix, exc)


cache = CacheService()
