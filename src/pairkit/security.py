"""Secrets, hashing and rate limiting.

QR secrets carry 128+ bits of randomness, so guessing is not a practical
attack; hashing at rest means a leaked database cannot be replayed into a
working pairing. The rate limiter is defense in depth and keeps logs quiet.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque


def new_secret(nbytes: int = 24) -> str:
    """URL-safe random secret (24 bytes -> 192 bits)."""
    return secrets.token_urlsafe(nbytes)


def new_id() -> str:
    return secrets.token_urlsafe(12)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def matches(secret: str | None, expected_hash: str | None) -> bool:
    if not secret or not expected_hash:
        return False
    return hmac.compare_digest(hash_secret(secret), expected_hash)


class RateLimiter:
    """Sliding-window limit per key (e.g. client IP). In-memory; swap for Redis when
    running more than one server process."""

    def __init__(self, limit: int = 20, window_s: float = 60.0, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window_s, clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self.clock()
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True
