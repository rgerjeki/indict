"""RIPEstat: rich, keyless IP and ASN facts.

RIPEstat is a free data service run by the RIPE NCC (no API key). It fills out the
picture of an IP beyond what WHOIS gives you: the announcing ASN and its holder, the
covering prefix, and the network's abuse contact. Like the other infrastructure
sources it does not render a verdict, it contributes facts and context.

https://stat.ripe.net/docs/data_api
"""

from __future__ import annotations

from ..models import IndicatorType, SourceResult, Verdict
from .base import Context, Source

_BASE = "https://stat.ripe.net/data"


class RipeStatSource(Source):
    name = "ripestat"
    supported_types = (IndicatorType.IP,)

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        payload, from_cache = ctx.cached(
            self.name, indicator, lambda: _fetch(ctx, indicator)
        )

        asns = payload.get("asns") or []
        prefix = payload.get("prefix")
        holder = payload.get("holder")
        abuse = payload.get("abuse_contacts") or []

        parts = []
        if asns:
            parts.append(f"AS{asns[0]}" + (f" {holder}" if holder else ""))
        if prefix:
            parts.append(f"prefix {prefix}")
        if abuse:
            parts.append(f"abuse {abuse[0]}")
        summary = ", ".join(parts) or "no RIPEstat data"

        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=Verdict.UNKNOWN,  # facts and context, not a reputation call
            summary=summary,
            data={
                "asn": asns[0] if asns else None,
                "asns": asns,
                "as_holder": holder,
                "prefix": prefix,
                "abuse_contacts": abuse,
            },
            links=[f"https://stat.ripe.net/{indicator}"],
            from_cache=from_cache,
        )


def _fetch(ctx: Context, indicator: str) -> dict:
    """Combine the three RIPEstat endpoints we use into one cacheable payload."""
    net = ctx.http.get_json(
        f"{_BASE}/network-info/data.json", params={"resource": indicator}
    )
    data = net.get("data", {}) if isinstance(net, dict) else {}
    asns = data.get("asns") or []
    prefix = data.get("prefix")

    holder = None
    if asns:
        overview = ctx.http.get_json(
            f"{_BASE}/as-overview/data.json", params={"resource": f"AS{asns[0]}"}
        )
        holder = (overview.get("data", {}) or {}).get("holder")

    abuse_payload = ctx.http.get_json(
        f"{_BASE}/abuse-contact-finder/data.json", params={"resource": indicator}
    )
    abuse = (abuse_payload.get("data", {}) or {}).get("abuse_contacts") or []

    return {"asns": asns, "prefix": prefix, "holder": holder, "abuse_contacts": abuse}
