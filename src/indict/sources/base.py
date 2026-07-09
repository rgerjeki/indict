"""The source contract.

A source is one OSINT service (or protocol). Each one declares which indicator
types it handles and whether it is `available` (keyless sources always are; keyed
sources need their key). Its `query` returns a normalized `SourceResult`. The
orchestrator handles timing and error wrapping, so `query` is free to raise.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..cache import Cache
from ..config import Config
from ..feeds import FeedCache
from ..http import Http
from ..models import IndicatorType, SourceResult


@dataclass
class Context:
    """Everything a source needs to do its job: config, HTTP, cache, and feeds."""

    config: Config
    http: Http
    cache: Cache
    feeds: FeedCache

    def cached(
        self, source: str, indicator: str, producer: Callable[[], object]
    ) -> tuple[object, bool]:
        """Return (payload, from_cache). Runs `producer` only on a cache miss."""
        hit = self.cache.get(source, indicator)
        if hit is not None:
            return hit, True
        payload = producer()
        self.cache.set(source, indicator, payload)
        return payload, False


class Source:
    """Base class for all sources. Subclasses set `name`/`supported_types`."""

    name: str = "source"
    supported_types: tuple[IndicatorType, ...] = ()
    requires_key: str | None = None  # Config attribute name, e.g. "virustotal_api_key"

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in self.supported_types

    def available(self, config: Config) -> bool:
        """Keyless sources are always available; keyed ones need their key."""
        if self.requires_key is None:
            return True
        return config.has(self.requires_key)

    def unavailable_reason(self) -> str:
        if self.requires_key:
            return f"no {self.requires_key.replace('_api_key', '').upper()} API key"
        return "not applicable"

    def query(
        self, indicator: str, indicator_type: IndicatorType, ctx: Context
    ) -> SourceResult:
        raise NotImplementedError
