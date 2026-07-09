from indict.correlate import correlate
from indict.models import (
    IndicatorType,
    Pivot,
    Relation,
    Report,
    SourceResult,
)


def _result(source, pivots):
    return SourceResult(
        source=source, indicator="example.com",
        indicator_type=IndicatorType.DOMAIN, pivots=pivots,
    )


def test_domain_clusters_by_hosting_ip():
    report = Report(indicator="example.com", indicator_type=IndicatorType.DOMAIN)
    report.results = [
        _result("dns", [Pivot("1.1.1.1", IndicatorType.IP, Relation.RESOLVES_TO, "dns")]),
        _result("crt.sh", [
            Pivot("www.example.com", IndicatorType.DOMAIN, Relation.SUBDOMAIN, "crt.sh"),
            Pivot("api.example.com", IndicatorType.DOMAIN, Relation.SUBDOMAIN, "crt.sh"),
        ]),
    ]
    resolve = {"www.example.com": ["1.1.1.1"], "api.example.com": ["2.2.2.2"]}
    correlate(report, resolve=lambda h: resolve.get(h, []))

    clusters = {c.key: set(c.members) for c in report.clusters}
    assert clusters["1.1.1.1"] == {"example.com", "www.example.com"}
    assert clusters["2.2.2.2"] == {"api.example.com"}
    # Largest cluster is ordered first.
    assert report.clusters[0].key == "1.1.1.1"


def test_pivots_are_deduped_and_exclude_self():
    report = Report(indicator="example.com", indicator_type=IndicatorType.DOMAIN)
    report.results = [
        _result("a", [Pivot("1.1.1.1", IndicatorType.IP, Relation.RESOLVES_TO, "a")]),
        _result("b", [Pivot("1.1.1.1", IndicatorType.IP, Relation.RESOLVES_TO, "b")]),
        _result("c", [Pivot("example.com", IndicatorType.DOMAIN, Relation.SUBDOMAIN, "c")]),
    ]
    correlate(report, resolve=None)
    indicators = [p.indicator for p in report.pivots]
    assert indicators.count("1.1.1.1") == 1  # deduped
    assert "example.com" not in indicators  # self excluded


def test_ip_clusters_reverse_dns_domains():
    report = Report(indicator="8.8.8.8", indicator_type=IndicatorType.IP)
    report.results = [
        SourceResult(
            source="dns", indicator="8.8.8.8", indicator_type=IndicatorType.IP,
            pivots=[Pivot("dns.google", IndicatorType.DOMAIN, Relation.REVERSE_DNS, "dns")],
        )
    ]
    correlate(report, resolve=None)
    assert report.clusters[0].members == ["dns.google"]
