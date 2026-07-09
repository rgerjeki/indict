"""A tiny local response cache.

Repeated triage of the same indicator should not re-hammer the APIs (rate limits,
and it is just polite). The cache is a directory of JSON files keyed by a hash of
source + indicator. It lives in a gitignored `.cache/` by design: third-party
terms of service often forbid rehosting their data, so cached responses never
leave the machine.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


class Cache:
    def __init__(self, directory: Path, ttl: int, enabled: bool = True) -> None:
        self.directory = Path(directory)
        self.ttl = ttl
        self.enabled = enabled

    def _path(self, source: str, indicator: str) -> Path:
        digest = hashlib.sha256(f"{source}:{indicator}".encode()).hexdigest()[:24]
        return self.directory / f"{source}_{digest}.json"

    def get(self, source: str, indicator: str) -> Any | None:
        """Return cached payload if present and fresh, else None."""
        if not self.enabled:
            return None
        path = self._path(source, indicator)
        if not path.exists():
            return None
        try:
            envelope = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        if time.time() - envelope.get("cached_at", 0) > self.ttl:
            return None
        return envelope.get("payload")

    def set(self, source: str, indicator: str, payload: Any) -> None:
        """Store a payload. Failures to write are non-fatal (best effort)."""
        if not self.enabled:
            return
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            envelope = {"cached_at": time.time(), "payload": payload}
            self._path(source, indicator).write_text(json.dumps(envelope))
        except OSError:
            pass
