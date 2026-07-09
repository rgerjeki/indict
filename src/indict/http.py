"""A thin HTTP layer shared by the keyed and keyless sources.

Gives every source the same client (one connection pool, one user-agent, one
timeout) and a small amount of rate-limit courtesy: on HTTP 429 we honor
Retry-After and back off a couple of times before giving up.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from . import __version__

USER_AGENT = f"indict/{__version__} (+https://github.com/rgerjeki/indict)"


class RateLimited(Exception):
    """Raised when a source keeps returning 429 after our retries."""


class Http:
    def __init__(self, timeout: float = 20.0, max_retries: int = 2) -> None:
        self.max_retries = max_retries
        self._client = httpx.Client(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        )

    def request_json(
        self, method: str, url: str, *, retry_timeouts: int = 0, **kwargs: Any
    ) -> Any:
        """Make a request and return decoded JSON, retrying on 429.

        Pass ``timeout`` to override the client default for a single slow source,
        and ``retry_timeouts`` to retry that many times on a read/connect timeout
        (crt.sh, for example, is often slow but succeeds on a second attempt).

        Raises RateLimited on persistent 429, httpx.HTTPStatusError on other
        non-2xx responses, and httpx errors on transport failure. Sources are
        expected to catch these and degrade gracefully.
        """
        attempt = 0
        timeout_attempt = 0
        while True:
            try:
                response = self._client.request(method, url, **kwargs)
            except (httpx.ReadTimeout, httpx.ConnectTimeout):
                if timeout_attempt < retry_timeouts:
                    timeout_attempt += 1
                    continue
                raise
            if response.status_code == 429 and attempt < self.max_retries:
                wait = _retry_after(response, default=1.5 * (attempt + 1))
                time.sleep(wait)
                attempt += 1
                continue
            if response.status_code == 429:
                raise RateLimited(url)
            response.raise_for_status()
            return response.json()

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.request_json("GET", url, **kwargs)

    def post_json(self, url: str, **kwargs: Any) -> Any:
        return self.request_json("POST", url, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Http:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _retry_after(response: httpx.Response, default: float) -> float:
    """Parse a Retry-After header (seconds form) or fall back to a default."""
    raw = response.headers.get("Retry-After")
    if raw and raw.isdigit():
        return min(float(raw), 30.0)
    return default
