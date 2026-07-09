"""VirusTotal: multi-engine reputation for every indicator type.

VirusTotal aggregates dozens of AV engines and scanners. For triage the key
number is the analysis stats: how many engines flagged the indicator malicious.
We normalize that into our verdict scale and cite the count (we link out to VT,
we do not mirror their dataset). Free-tier key required, so this degrades to
"unavailable" without VIRUSTOTAL_API_KEY.

https://docs.virustotal.com/reference/overview
"""

from __future__ import annotations

import base64

import httpx

from ..models import IndicatorType, Pivot, Relation, SourceResult, Verdict
from .base import Context, Source

# A few malicious detections is a firm call; a lone detection is worth a look but
# is often a false positive, so it lands as suspicious.
_MALICIOUS_AT = 3


class VirusTotalSource(Source):
    name = "virustotal"
    supported_types = (
        IndicatorType.IP,
        IndicatorType.DOMAIN,
        IndicatorType.HASH,
        IndicatorType.URL,
    )
    requires_key = "virustotal_api_key"

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        path = _api_path(indicator, indicator_type)
        url = f"https://www.virustotal.com/api/v3/{path}"
        headers = {"x-apikey": ctx.config.virustotal_api_key}

        try:
            payload, from_cache = ctx.cached(
                self.name, indicator, lambda: ctx.http.get_json(url, headers=headers)
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return SourceResult(
                    source=self.name,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    verdict=Verdict.UNKNOWN,
                    summary="not found in VirusTotal",
                    links=[_gui_link(indicator, indicator_type)],
                )
            raise

        attrs = (payload.get("data", {}) or {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 0

        if not stats:
            verdict = Verdict.UNKNOWN
        elif malicious >= _MALICIOUS_AT:
            verdict = Verdict.MALICIOUS
        elif malicious + suspicious >= 1:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        score = round(100 * malicious / total) if total else None
        summary = (
            f"{malicious}/{total} engines flagged malicious"
            + (f", {suspicious} suspicious" if suspicious else "")
            if total
            else "no analysis results yet"
        )

        data = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": attrs.get("reputation"),
        }
        _enrich(data, attrs, indicator_type)

        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            score=score,
            summary=summary,
            data=data,
            links=[_gui_link(indicator, indicator_type)],
            pivots=_pivots(attrs, indicator_type, self.name),
            from_cache=from_cache,
        )


def _api_path(indicator: str, indicator_type: IndicatorType) -> str:
    if indicator_type is IndicatorType.IP:
        return f"ip_addresses/{indicator}"
    if indicator_type is IndicatorType.DOMAIN:
        return f"domains/{indicator}"
    if indicator_type is IndicatorType.HASH:
        return f"files/{indicator}"
    # URL id is the base64url of the URL, no padding.
    url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
    return f"urls/{url_id}"


def _gui_link(indicator: str, indicator_type: IndicatorType) -> str:
    if indicator_type is IndicatorType.IP:
        return f"https://www.virustotal.com/gui/ip-address/{indicator}"
    if indicator_type is IndicatorType.DOMAIN:
        return f"https://www.virustotal.com/gui/domain/{indicator}"
    if indicator_type is IndicatorType.HASH:
        return f"https://www.virustotal.com/gui/file/{indicator}"
    url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
    return f"https://www.virustotal.com/gui/url/{url_id}"


def _enrich(data: dict, attrs: dict, indicator_type: IndicatorType) -> None:
    """Add a few type-specific, non-bulk fields worth showing."""
    if indicator_type is IndicatorType.HASH:
        data["type_description"] = attrs.get("type_description")
        data["meaningful_name"] = attrs.get("meaningful_name")
        data["first_seen"] = attrs.get("first_submission_date")
        threat = attrs.get("popular_threat_classification", {}) or {}
        data["threat_label"] = threat.get("suggested_threat_label")
    elif indicator_type is IndicatorType.DOMAIN:
        data["registrar"] = attrs.get("registrar")
    elif indicator_type is IndicatorType.IP:
        data["asn"] = attrs.get("asn")
        data["as_owner"] = attrs.get("as_owner")
        data["country"] = attrs.get("country")


def _pivots(attrs: dict, indicator_type: IndicatorType, source: str) -> list[Pivot]:
    if indicator_type is not IndicatorType.DOMAIN:
        return []
    pivots = []
    for record in attrs.get("last_dns_records", []) or []:
        if record.get("type") == "A" and record.get("value"):
            pivots.append(
                Pivot(record["value"], IndicatorType.IP, Relation.RESOLVES_TO, source)
            )
    return pivots
