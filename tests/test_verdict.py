from indict.models import IndicatorType, Report, SourceResult, Verdict
from indict.verdict import aggregate


def _r(source, verdict, ok=True, available=True, summary=""):
    return SourceResult(
        source=source, indicator="x", indicator_type=IndicatorType.IP,
        verdict=verdict, ok=ok, available=available, summary=summary or source,
    )


def _report(results):
    report = Report(indicator="x", indicator_type=IndicatorType.IP)
    report.results = results
    return report


def test_most_severe_verdict_wins():
    report = _report([
        _r("a", Verdict.CLEAN),
        _r("b", Verdict.SUSPICIOUS),
        _r("c", Verdict.MALICIOUS),
    ])
    aggregate(report)
    assert report.verdict is Verdict.MALICIOUS
    # Evidence is ordered most-severe first.
    assert report.evidence[0].startswith("[malicious]")


def test_all_unknown_stays_unknown():
    report = _report([_r("a", Verdict.UNKNOWN), _r("b", Verdict.UNKNOWN)])
    aggregate(report)
    assert report.verdict is Verdict.UNKNOWN
    assert report.evidence == []


def test_clean_beats_unknown():
    report = _report([_r("a", Verdict.UNKNOWN), _r("b", Verdict.CLEAN)])
    aggregate(report)
    assert report.verdict is Verdict.CLEAN


def test_failed_and_unavailable_sources_are_ignored():
    report = _report([
        _r("ok", Verdict.CLEAN),
        _r("errored", Verdict.MALICIOUS, ok=False),        # errored: not counted
        _r("skipped", Verdict.MALICIOUS, available=False),  # not run: not counted
    ])
    aggregate(report)
    assert report.verdict is Verdict.CLEAN
