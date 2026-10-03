import time

import pytest
import requests

from core import ratelimit
from core.ratelimit import RateLimiter, rate_limited_get


class FakeResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


def test_limiter_spaces_out_calls():
    limiter = RateLimiter(0.05)
    start = time.monotonic()
    for _ in range(3):
        limiter.wait()
    # First call is free; the next two each wait one interval.
    assert time.monotonic() - start >= 0.1


def test_first_call_is_not_delayed():
    limiter = RateLimiter(5.0)
    start = time.monotonic()
    limiter.wait()
    assert time.monotonic() - start < 1.0


def test_module_limiters_are_distinct():
    assert ratelimit.crtsh_limiter is not ratelimit.geoip_limiter


def test_returns_response_on_success(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda url, **kw: FakeResponse(200))
    resp = rate_limited_get("https://example.com", RateLimiter(0))
    assert resp.status_code == 200


def test_passes_through_timeout_and_kwargs(monkeypatch):
    seen = {}

    def fake_get(url, **kwargs):
        seen.update(kwargs)
        return FakeResponse(200)

    monkeypatch.setattr(requests, "get", fake_get)
    rate_limited_get("https://example.com", RateLimiter(0), timeout=7, headers={"A": "B"})
    assert seen["timeout"] == 7
    assert seen["headers"] == {"A": "B"}


def test_does_not_retry_a_normal_error_status(monkeypatch):
    calls = []

    def fake_get(url, **kw):
        calls.append(1)
        return FakeResponse(404)

    monkeypatch.setattr(requests, "get", fake_get)
    resp = rate_limited_get("https://example.com", RateLimiter(0))
    assert resp.status_code == 404
    assert len(calls) == 1


@pytest.mark.parametrize("status", [429, 503])
def test_retries_when_throttled(monkeypatch, status):
    calls = []

    def fake_get(url, **kw):
        calls.append(1)
        return FakeResponse(status if len(calls) == 1 else 200)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setattr(ratelimit.time, "sleep", lambda s: None)

    resp = rate_limited_get("https://example.com", RateLimiter(0), retries=2)
    assert resp.status_code == 200
    assert len(calls) == 2


def test_gives_up_after_retries_and_returns_last_response(monkeypatch):
    calls = []

    def fake_get(url, **kw):
        calls.append(1)
        return FakeResponse(429)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(ratelimit.time, "sleep", lambda s: None)

    resp = rate_limited_get("https://example.com", RateLimiter(0), retries=1)
    assert resp.status_code == 429
    assert len(calls) == 2


def test_honors_retry_after_header(monkeypatch):
    slept = []

    def fake_get(url, **kw):
        return FakeResponse(429, {"Retry-After": "5"})

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(ratelimit.time, "sleep", slept.append)

    rate_limited_get("https://example.com", RateLimiter(0), retries=1)
    assert 5.0 in slept


def test_caps_an_absurd_retry_after(monkeypatch):
    slept = []
    monkeypatch.setattr(requests, "get", lambda url, **kw: FakeResponse(429, {"Retry-After": "99999"}))
    monkeypatch.setattr(ratelimit.time, "sleep", slept.append)

    rate_limited_get("https://example.com", RateLimiter(0), retries=1)
    assert max(slept) <= 30.0


def test_ignores_unparseable_retry_after(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda url, **kw: FakeResponse(429, {"Retry-After": "soon"}))
    monkeypatch.setattr(ratelimit.time, "sleep", lambda s: None)

    resp = rate_limited_get("https://example.com", RateLimiter(0), retries=1)
    assert resp.status_code == 429


def test_returns_none_when_every_attempt_raises(monkeypatch):
    calls = []

    def fake_get(url, **kw):
        calls.append(1)
        raise requests.RequestException("boom")

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(ratelimit.time, "sleep", lambda s: None)

    assert rate_limited_get("https://example.com", RateLimiter(0), retries=2) is None
    assert len(calls) == 3


def test_recovers_after_a_transient_exception(monkeypatch):
    calls = []

    def fake_get(url, **kw):
        calls.append(1)
        if len(calls) == 1:
            raise requests.Timeout("slow")
        return FakeResponse(200)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(ratelimit.time, "sleep", lambda s: None)

    assert rate_limited_get("https://example.com", RateLimiter(0), retries=2).status_code == 200
