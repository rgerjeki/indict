"""GreyNoise community endpoint.

GreyNoise tells you whether an IP is internet background noise (mass scanners,
crawlers) and whether it is classified benign or malicious. The community
endpoint is keyless and rate-limited but perfect for triage: it answers "is this
IP known-bad, known-benign, or genuinely unusual?".

A 404 here is a signal, not an error: it means GreyNoise has not observed the IP.
https://docs.greynoise.io/
"""

from __future__ import annotations

import httpx

from ..models import IndicatorType, SourceResult, Verdict
from .base import Context, Source

_CLASSIFICATION_VERDICT = {
    "malicious": Verdict.MALICIOUS,
    "benign": Verdict.CLEAN,
    "unknown": Verdict.UNKNOWN,
}


class GreyNoiseSource(Source):
    name = "greynoise"
    supported_types = (IndicatorType.IP,)

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        url = f"https://api.greynoise.io/v3/community/{indicator}"
        try:
            payload, from_cache = ctx.cached(
                self.name, indicator, lambda: ctx.http.get_json(url)
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return SourceResult(
                    source=self.name,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    verdict=Verdict.UNKNOWN,
                    summary="not observed by GreyNoise (no scanning activity seen)",
                    links=[f"https://viz.greynoise.io/ip/{indicator}"],
                )
            raise

        classification = str(payload.get("classification", "unknown")).lower()
        verdict = _CLASSIFICATION_VERDICT.get(classification, Verdict.UNKNOWN)
        noise = bool(payload.get("noise"))
        riot = bool(payload.get("riot"))
        name = payload.get("name")

        descriptor = []
        if noise:
            descriptor.append("internet scanner/noise")
        if riot:
            descriptor.append("common business service (RIOT)")
        summary = f"classified {classification}"
        if name and name != "unknown":
            summary += f" ({name})"
        if descriptor:
            summary += "; " + ", ".join(descriptor)

        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            summary=summary,
            data={
                "classification": classification,
                "noise": noise,
                "riot": riot,
                "name": name,
                "last_seen": payload.get("last_seen"),
            },
            links=[payload.get("link") or f"https://viz.greynoise.io/ip/{indicator}"],
            from_cache=from_cache,
        )
