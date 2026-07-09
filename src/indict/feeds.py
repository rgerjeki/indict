"""A disk cache for downloadable threat feeds.

Blocklists (FireHOL, the Tor exit list, and so on) are large text files that update
on the order of hours, not per lookup. Downloading them on every run would be slow
and rude, so we cache each feed on disk and only refetch when it goes stale. If a
refetch fails (network down, a feed starts requiring auth), we fall back to the last
good copy we have rather than losing the source entirely.

The feed cache lives under the same gitignored `.cache/` directory as everything
else, so downloaded feed data never leaves the machine.
"""

from __future__ import annotations

import time
from pathlib import Path

from .http import Http

# Feeds refresh a few times a day at most; twelve hours keeps us current without
# hammering the sources.
DEFAULT_FEED_TTL = 12 * 60 * 60


class FeedCache:
    def __init__(self, directory: Path, http: Http, ttl: int = DEFAULT_FEED_TTL) -> None:
        self.directory = Path(directory)
        self.http = http
        self.ttl = ttl

    def get_text(self, name: str, url: str, headers: dict[str, str] | None = None) -> str | None:
        """Return the feed body, from a fresh cache, a new download, or a stale
        cache as a last resort. Returns None only if we have nothing at all."""
        path = self.directory / f"{name}.txt"

        if path.exists() and (time.time() - path.stat().st_mtime) < self.ttl:
            cached = _read(path)
            if cached is not None:
                return cached

        try:
            text = self.http.get_text(url, headers=headers or {})
        except Exception:  # noqa: BLE001 - any failure falls back to stale data
            return _read(path)  # last good copy, or None if we never had one

        _write(path, text)
        return text


def _read(path: Path) -> str | None:
    try:
        return path.read_text()
    except OSError:
        return None


def _write(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    except OSError:
        pass
