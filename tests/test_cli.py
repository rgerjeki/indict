"""End-to-end triage through the public entry point, with mocked HTTP."""

from __future__ import annotations

import httpx
import respx
from conftest import load_fixture

from indict.cli import triage
from indict.models import IndicatorType, Verdict
from indict.report import to_dict, to_markdown


@respx.mock
def test_triage_hash_aggregates_malicious(config):
    # A hash is handled by MalwareBazaar (keyless) and VirusTotal (keyed).
    respx.post("https://mb-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={
            "query_status": "ok",
            "data": [{"signature": "EICAR", "file_type": "txt",
                      "first_seen": "2020-01-01", "sha256_hash": "a" * 64}],
        })
    )
    respx.get(
        "https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f"
    ).mock(return_value=httpx.Response(200, json=load_fixture("vt_file_malicious.json")))

    report = triage("44d88612fea8a8f36de82e1278abb02f", config, do_correlate=False)

    assert report.indicator_type is IndicatorType.HASH
    assert report.verdict is Verdict.MALICIOUS
    assert len(report.evidence) == 2

    # Both serializers work off the same report.
    payload = to_dict(report)
    assert payload["verdict"] == "malicious"
    assert "# indict report" in to_markdown(report)


@respx.mock
def test_triage_marks_unavailable_keyed_sources(config):
    config.virustotal_api_key = None  # no VT key
    respx.post("https://mb-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "hash_not_found"})
    )

    report = triage("a" * 64, config, do_correlate=False)

    by_source = {r.source: r for r in report.results}
    assert by_source["virustotal"].available is False
    assert "VIRUSTOTAL" in by_source["virustotal"].summary
    # The keyless source still ran.
    assert by_source["malwarebazaar"].available is True


@respx.mock
def test_triage_only_filter_limits_sources(config):
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=load_fixture("crtsh_example.json"))
    )
    report = triage("example.com", config, only={"crt.sh"}, do_correlate=False)
    assert [r.source for r in report.results] == ["crt.sh"]
