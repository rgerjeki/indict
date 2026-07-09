from indict.models import IndicatorType, Report, SourceResult
from indict.redact import REDACTED, redact_report


def test_redact_strips_registrant_pii_but_keeps_infrastructure():
    result = SourceResult(
        source="whois", indicator="example.com", indicator_type=IndicatorType.DOMAIN,
        summary="registrar IANA, contact jane@example.com",
        data={
            "registrar": "IANA",
            "name_servers": ["a.iana-servers.net"],
            "registrant": {"name": "Jane Analyst", "email": "jane@example.com"},
        },
    )
    report = Report(indicator="example.com", indicator_type=IndicatorType.DOMAIN,
                    results=[result], evidence=["[clean] whois: contact jane@example.com"])

    redact_report(report)

    reg = report.results[0].data["registrant"]
    assert reg["name"] == REDACTED
    assert reg["email"] == REDACTED
    # Infrastructure is preserved.
    assert report.results[0].data["registrar"] == "IANA"
    assert report.results[0].data["name_servers"] == ["a.iana-servers.net"]
    # Emails scrubbed from free text too.
    assert "jane@example.com" not in report.results[0].summary
    assert "jane@example.com" not in report.evidence[0]
    assert report.redacted is True
