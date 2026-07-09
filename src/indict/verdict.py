"""Verdict aggregation.

Each source returns its own verdict. The overall call is the most severe verdict
any source actively made (malicious beats suspicious beats clean beats unknown),
with the evidence attached so a reader can see why, not just the label. We do not
invent a verdict from silence: if nothing flagged the indicator and nothing
cleared it, the overall stays unknown.
"""

from __future__ import annotations

from .models import Report, SourceResult, Verdict


def aggregate(report: Report) -> Report:
    """Set `report.verdict` and `report.evidence` from the source results."""
    scored = [
        r
        for r in report.results
        if r.available and r.ok and r.verdict is not Verdict.UNKNOWN
    ]

    if not scored:
        report.verdict = Verdict.UNKNOWN
    else:
        report.verdict = max(scored, key=lambda r: r.verdict.severity).verdict

    report.evidence = _build_evidence(scored)
    return report


def _build_evidence(scored: list[SourceResult]) -> list[str]:
    """One line per source that made a call, most severe first."""
    ordered = sorted(scored, key=lambda r: (-r.verdict.severity, r.source))
    return [f"[{r.verdict.value}] {r.source}: {r.summary}" for r in ordered]
