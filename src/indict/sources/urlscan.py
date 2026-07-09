"""urlscan.io public search.

urlscan runs and records scans of URLs. The public search API (keyless) lets us
ask "has this domain or URL been scanned, and what IPs did it serve from?"
without submitting a new scan (submitting could tip off an adversary, and it can
expose the URL publicly). The IPs found become pivots to hosting infrastructure.

https://urlscan.io/docs/api/
"""

from __future__ import annotations

from ..indicators import host_of
from ..models import IndicatorType, Pivot, Relation, SourceResult, Verdict
from .base import Context, Source

_MAX_RESULTS = 10


class UrlscanSource(Source):
    name = "urlscan"
    supported_types = (IndicatorType.DOMAIN, IndicatorType.URL)

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        host = indicator if indicator_type is IndicatorType.DOMAIN else host_of(indicator)
        if not host:
            return SourceResult.unavailable(
                self.name, indicator, indicator_type, "no host to search"
            )

        url = "https://urlscan.io/api/v1/search/"
        params = {"q": f"domain:{host}", "size": _MAX_RESULTS}
        payload, from_cache = ctx.cached(
            self.name, indicator, lambda: ctx.http.get_json(url, params=params)
        )

        results = payload.get("results", []) if isinstance(payload, dict) else []
        ips: list[str] = []
        recent: list[dict] = []
        for row in results[:_MAX_RESULTS]:
            page = row.get("page", {})
            ip = page.get("ip")
            if ip and ip not in ips:
                ips.append(ip)
            recent.append(
                {
                    "url": (row.get("task") or {}).get("url"),
                    "time": (row.get("task") or {}).get("time"),
                    "ip": ip,
                    "server": page.get("server"),
                }
            )

        pivots = [
            Pivot(ip, IndicatorType.IP, Relation.RESOLVES_TO, self.name) for ip in ips
        ]
        total = payload.get("total", len(results)) if isinstance(payload, dict) else 0
        summary = (
            f"{total} scan(s) on record; served from {len(ips)} distinct IP(s)"
            if results
            else "no public scans on record"
        )

        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=Verdict.UNKNOWN,  # search results are informational
            summary=summary,
            data={"total": total, "ips": ips, "recent": recent},
            links=[f"https://urlscan.io/search/#domain%3A{host}"],
            pivots=pivots,
            from_cache=from_cache,
        )
