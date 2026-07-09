"""crt.sh: certificate transparency logs.

CT logs are a goldmine for a domain analyst: every publicly trusted certificate is
logged, so querying crt.sh for a domain surfaces subdomains that were never in
DNS answers you asked for. Those subdomains become pivots that correlation later
resolves and clusters by hosting IP.

Keyless. https://crt.sh/
"""

from __future__ import annotations

from ..models import IndicatorType, Pivot, Relation, SourceResult, Verdict
from .base import Context, Source

# crt.sh has no published cap, but a busy domain can return thousands of rows.
# We keep the pivot set bounded so correlation stays fast and the report readable.
_MAX_SUBDOMAINS = 50

# crt.sh is frequently slow. Give it a shorter budget than the global timeout so
# it cannot stall the whole (parallel) run, but retry once, since a second
# attempt often succeeds.
_TIMEOUT = 8.0
_RETRY_TIMEOUTS = 1


class CrtShSource(Source):
    name = "crt.sh"
    supported_types = (IndicatorType.DOMAIN,)

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        url = "https://crt.sh/"
        params = {"q": f"%.{indicator}", "output": "json"}

        payload, from_cache = ctx.cached(
            self.name,
            indicator,
            lambda: ctx.http.get_json(
                url, params=params, timeout=_TIMEOUT, retry_timeouts=_RETRY_TIMEOUTS
            ),
        )

        subdomains = _extract_subdomains(payload, indicator)
        pivots = [
            Pivot(
                indicator=name,
                indicator_type=IndicatorType.DOMAIN,
                relation=Relation.SUBDOMAIN,
                source=self.name,
            )
            for name in subdomains[:_MAX_SUBDOMAINS]
        ]

        count = len(subdomains)
        summary = (
            f"{count} unique subdomain(s) in certificate transparency logs"
            if count
            else "no subdomains found in certificate transparency logs"
        )
        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=Verdict.UNKNOWN,  # CT data is informational, not a reputation call
            summary=summary,
            data={
                "subdomain_count": count,
                "subdomains": subdomains[:_MAX_SUBDOMAINS],
                "truncated": count > _MAX_SUBDOMAINS,
            },
            links=[f"https://crt.sh/?q=%25.{indicator}"],
            pivots=pivots,
            from_cache=from_cache,
        )


def _extract_subdomains(payload: object, domain: str) -> list[str]:
    """Flatten crt.sh rows into a sorted, de-duplicated subdomain list."""
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    suffix = f".{domain}"
    for row in payload:
        if not isinstance(row, dict):
            continue
        # name_value can hold several newline-separated SANs.
        for field in ("name_value", "common_name"):
            value = row.get(field, "")
            for name in str(value).splitlines():
                name = name.strip().lower().lstrip("*.")
                if not name or name == domain:
                    continue
                if name.endswith(suffix):
                    names.add(name)
    return sorted(names)
