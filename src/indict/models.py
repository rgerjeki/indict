"""Normalized data models.

Every source, no matter how different its raw API response, is normalized into a
`SourceResult`. The CLI collects these, correlates the pivots, aggregates a
verdict, and renders a report. Keeping one shape is what makes six services look
like one tool.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"


class Verdict(StrEnum):
    """Ordered from least to most severe. `UNKNOWN` means we have no signal."""

    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

    @property
    def severity(self) -> int:
        return _VERDICT_SEVERITY[self]


# Higher number wins when aggregating. `clean` is deliberately above `unknown`:
# a source that actively cleared the indicator is a stronger signal than silence,
# but any suspicious/malicious hit still outranks it.
_VERDICT_SEVERITY: dict[Verdict, int] = {
    Verdict.UNKNOWN: 0,
    Verdict.CLEAN: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}


class Relation(StrEnum):
    """How a pivoted indicator relates to the one we looked up."""

    SUBDOMAIN = "subdomain"
    RESOLVES_TO = "resolves_to"
    RESOLVED_FROM = "resolved_from"
    REVERSE_DNS = "reverse_dns"
    MAIL_SERVER = "mail_server"
    NAME_SERVER = "name_server"
    HOSTS_DOMAIN = "hosts_domain"
    RELATED_URL = "related_url"


@dataclass(frozen=True)
class Pivot:
    """A related indicator discovered while enriching the primary one.

    Pivots are the analyst value-add: one indicator in, a picture of related
    infrastructure out. `correlate.py` clusters them.
    """

    indicator: str
    indicator_type: IndicatorType
    relation: Relation
    source: str
    note: str = ""


@dataclass
class SourceResult:
    """The normalized output of one source for one indicator."""

    source: str
    indicator: str
    indicator_type: IndicatorType

    # Did this source run and return usable data?
    available: bool = True  # was it configured/enabled at all (graceful degradation)
    ok: bool = True  # did the query itself succeed
    error: str | None = None

    verdict: Verdict = Verdict.UNKNOWN
    # Normalized 0-100 confidence when a source exposes one, else None.
    score: int | None = None
    summary: str = ""

    # Normalized, safe-to-display structured fields (already trimmed of bulk).
    data: dict[str, Any] = field(default_factory=dict)
    # Cite-out URLs. We link to sources, we do not mirror their datasets.
    links: list[str] = field(default_factory=list)

    pivots: list[Pivot] = field(default_factory=list)

    latency_ms: int | None = None
    from_cache: bool = False

    @classmethod
    def unavailable(cls, source: str, indicator: str, indicator_type: IndicatorType,
                    reason: str) -> SourceResult:
        """A source that was skipped (no key, not applicable, disabled)."""
        return cls(
            source=source,
            indicator=indicator,
            indicator_type=indicator_type,
            available=False,
            ok=False,
            summary=reason,
        )

    @classmethod
    def failed(cls, source: str, indicator: str, indicator_type: IndicatorType,
               error: str) -> SourceResult:
        """A source that was configured and applicable but errored out."""
        return cls(
            source=source,
            indicator=indicator,
            indicator_type=indicator_type,
            available=True,
            ok=False,
            error=error,
            summary=f"query failed: {error}",
        )


@dataclass
class Cluster:
    """A group of infrastructure that correlation found hanging together."""

    key: str  # e.g. an IP address that several subdomains resolve to
    label: str  # human description, e.g. "hosting IP"
    members: list[str] = field(default_factory=list)


@dataclass
class Report:
    """The full triage result for one indicator."""

    indicator: str
    indicator_type: IndicatorType
    verdict: Verdict = Verdict.UNKNOWN
    evidence: list[str] = field(default_factory=list)
    results: list[SourceResult] = field(default_factory=list)
    pivots: list[Pivot] = field(default_factory=list)
    clusters: list[Cluster] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)
    redacted: bool = False

    @property
    def ran(self) -> list[SourceResult]:
        """Sources that were available and produced a result (ok or error)."""
        return [r for r in self.results if r.available]
