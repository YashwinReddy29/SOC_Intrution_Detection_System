"""Small dependency-free security helpers for the SOC API."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import defaultdict, deque


class InMemoryRateLimiter:
    """Fixed-window limiter suitable for a single-process deployment.

    Multi-worker deployments should replace this with a shared store such as
    Redis so all application processes enforce one global limit.
    """

    def __init__(self, limit: int = 300, window_seconds: int = 60) -> None:
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def retry_after(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return 0
            remaining = max(0.0, self.window_seconds - (now - hits[0]))
            return max(1, int(remaining))


def valid_api_key(candidate: str | None, expected: str | None) -> bool:
    """Validate an API key using a constant-time comparison.

    Authentication fails closed when no expected key is configured.
    """
    if not candidate or not expected:
        return False

    return hmac.compare_digest(
        hashlib.sha256(candidate.encode()).digest(),
        hashlib.sha256(expected.encode()).digest(),
    )
