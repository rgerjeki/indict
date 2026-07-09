"""AbuseIPDB: crowdsourced IP abuse reputation.

AbuseIPDB aggregates abuse reports (SSH brute force, spam, web attacks) into a
single abuse-confidence score (0-100). It is one of the clearest reputation
signals for an IP. Free-tier key required, so this source degrades to
"unavailable" when ABUSEIPDB_API_KEY is not set.

https://docs.abuseipdb.com/
"""

from __future__ import annotations

from ..models import IndicatorType, Pivot, Relation, SourceResult, Verdict
from .base import Context, Source

# Score thresholds tuned for triage: high confidence is malicious, any meaningful
# report volume is worth a second look.
_MALICIOUS_AT = 50
_SUSPICIOUS_AT = 15


class AbuseIpdbSource(Source):
    name = "abuseipdb"
    supported_types = (IndicatorType.IP,)
    requires_key = "abuseipdb_api_key"

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ctx.config.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": indicator, "maxAgeInDays": 90}

        payload, from_cache = ctx.cached(
            self.name,
            indicator,
            lambda: ctx.http.get_json(url, params=params, headers=headers),
        )
        data = payload.get("data", {}) if isinstance(payload, dict) else {}

        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        if score >= _MALICIOUS_AT:
            verdict = Verdict.MALICIOUS
        elif score >= _SUSPICIOUS_AT:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        domain = data.get("domain")
        pivots = []
        if domain:
            pivots.append(Pivot(domain, IndicatorType.DOMAIN, Relation.HOSTS_DOMAIN, self.name))

        summary = f"abuse confidence {score}/100 from {reports} report(s)"
        if data.get("isTor"):
            summary += "; Tor exit node"

        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            score=score,
            summary=summary,
            data={
                "abuse_confidence": score,
                "total_reports": reports,
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "domain": domain,
                "is_tor": bool(data.get("isTor")),
                "last_reported": data.get("lastReportedAt"),
            },
            links=[f"https://www.abuseipdb.com/check/{indicator}"],
            pivots=pivots,
            from_cache=from_cache,
        )
