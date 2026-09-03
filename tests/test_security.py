from __future__ import annotations

from app.security import InMemoryRateLimiter, valid_api_key


def test_api_key_comparison() -> None:
    assert not valid_api_key(None, None)
    assert not valid_api_key("secret", None)
    assert not valid_api_key(None, "secret")
    assert not valid_api_key("wrong", "secret")
    assert valid_api_key("secret", "secret")


def test_rate_limiter_blocks_after_limit() -> None:
    limiter = InMemoryRateLimiter(limit=2, window_seconds=60)

    assert limiter.allow("client-a")
    assert limiter.allow("client-a")
    assert not limiter.allow("client-a")
    assert limiter.allow("client-b")
