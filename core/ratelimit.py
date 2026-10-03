"""Client-side rate limiting for third-party OSINT endpoints.

crt.sh and ipapi.co both throttle aggressively and a full scan can fan
out to dozens of IPs, so requests are paced here rather than relying on
the remote side to tell us to back off.
"""

import threading
import time
from typing import Optional

import requests

# ipapi.co's free tier throttles well before its daily cap; crt.sh asks
# callers to stay gentle. One request per second each is comfortable.
CRTSH_MIN_INTERVAL = 1.0
GEOIP_MIN_INTERVAL = 1.0


class RateLimiter:
    """Enforce a minimum interval between calls, across threads."""

    def __init__(self, min_interval: float):
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self) -> None:
        with self._lock:
            elapsed = time.monotonic() - self._last_call
            sleep_for = self.min_interval - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last_call = time.monotonic()


crtsh_limiter = RateLimiter(CRTSH_MIN_INTERVAL)
geoip_limiter = RateLimiter(GEOIP_MIN_INTERVAL)


def rate_limited_get(
    url: str,
    limiter: RateLimiter,
    timeout: int = 10,
    retries: int = 2,
    **kwargs,
) -> Optional[requests.Response]:
    """GET `url` behind `limiter`, honoring 429/503 backoff.

    Returns the response, or None if every attempt failed or was
    throttled. Respects Retry-After when the server sends it.
    """
    for attempt in range(retries + 1):
        limiter.wait()
        try:
            resp = requests.get(url, timeout=timeout, **kwargs)
        except requests.RequestException:
            if attempt == retries:
                return None
            time.sleep(2**attempt)
            continue

        if resp.status_code not in (429, 503):
            return resp
        if attempt == retries:
            return resp

        retry_after = resp.headers.get("Retry-After")
        delay = 2**attempt
        if retry_after:
            try:
                delay = max(delay, min(float(retry_after), 30.0))
            except ValueError:
                pass
        time.sleep(delay)

    return None
