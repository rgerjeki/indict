"""Source tests: every HTTP source against mocked responses (respx)."""

from __future__ import annotations

import httpx
import respx
from conftest import load_fixture

from indict.models import IndicatorType, Relation, Verdict
from indict.sources.abuseipdb import AbuseIpdbSource
from indict.sources.crtsh import CrtShSource
from indict.sources.dns import DnsSource
from indict.sources.greynoise import GreyNoiseSource
from indict.sources.malwarebazaar import MalwareBazaarSource
from indict.sources.urlscan import UrlscanSource
from indict.sources.virustotal import VirusTotalSource
from indict.sources.whois import WhoisSource


@respx.mock
def test_crtsh_extracts_and_pivots(ctx):
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=load_fixture("crtsh_example.json"))
    )
    result = CrtShSource().query("example.com", IndicatorType.DOMAIN, ctx)

    subs = result.data["subdomains"]
    assert set(subs) == {"www.example.com", "mail.example.com", "api.example.com"}
    assert "unrelated.other.org" not in subs  # different apex is filtered
    assert all(p.relation is Relation.SUBDOMAIN for p in result.pivots)
    assert result.verdict is Verdict.UNKNOWN


@respx.mock
def test_crtsh_retries_once_on_timeout(ctx):
    # First attempt times out, the retry succeeds.
    respx.get("https://crt.sh/").mock(
        side_effect=[
            httpx.ReadTimeout("slow", request=httpx.Request("GET", "https://crt.sh/")),
            httpx.Response(200, json=load_fixture("crtsh_example.json")),
        ]
    )
    result = CrtShSource().query("example.com", IndicatorType.DOMAIN, ctx)
    assert result.ok is True
    assert result.data["subdomain_count"] == 3


@respx.mock
def test_whois_domain_parses_and_flags_pii(ctx):
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=load_fixture("rdap_domain.json"))
    )
    result = WhoisSource().query("example.com", IndicatorType.DOMAIN, ctx)

    assert result.data["registrar"] == "IANA"
    assert result.data["created"] == "1995-08-14T04:00:00Z"
    assert result.data["registrant"]["email"] == "jane@example.com"
    assert {p.indicator for p in result.pivots} == {
        "a.iana-servers.net",
        "b.iana-servers.net",
    }


@respx.mock
def test_whois_flags_young_domain_as_suspicious(ctx):
    young = {
        "events": [{"eventAction": "registration", "eventDate": "2026-07-01T00:00:00Z"}],
        "nameservers": [],
        "entities": [],
    }
    respx.get("https://rdap.org/domain/fresh.example").mock(
        return_value=httpx.Response(200, json=young)
    )
    result = WhoisSource().query("fresh.example", IndicatorType.DOMAIN, ctx)
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.data["age_days"] is not None and result.data["age_days"] < 30


@respx.mock
def test_greynoise_malicious_classification(ctx):
    respx.get("https://api.greynoise.io/v3/community/1.2.3.4").mock(
        return_value=httpx.Response(
            200,
            json={"classification": "malicious", "noise": True, "riot": False,
                  "name": "Scanner", "link": "https://viz.greynoise.io/ip/1.2.3.4"},
        )
    )
    result = GreyNoiseSource().query("1.2.3.4", IndicatorType.IP, ctx)
    assert result.verdict is Verdict.MALICIOUS


@respx.mock
def test_greynoise_404_is_unknown_not_error(ctx):
    respx.get("https://api.greynoise.io/v3/community/9.9.9.9").mock(
        return_value=httpx.Response(404, json={"message": "not found"})
    )
    result = GreyNoiseSource().query("9.9.9.9", IndicatorType.IP, ctx)
    assert result.ok is True
    assert result.verdict is Verdict.UNKNOWN


@respx.mock
def test_malwarebazaar_hit_is_malicious(ctx):
    respx.post("https://mb-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [{
                    "signature": "TestFamily",
                    "file_type": "exe",
                    "first_seen": "2020-01-01",
                    "sha256_hash": "a" * 64,
                    "tags": ["trojan"],
                }],
            },
        )
    )
    result = MalwareBazaarSource().query("a" * 64, IndicatorType.HASH, ctx)
    assert result.verdict is Verdict.MALICIOUS
    assert result.data["signature"] == "TestFamily"


@respx.mock
def test_malwarebazaar_miss_is_unknown(ctx):
    respx.post("https://mb-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "hash_not_found"})
    )
    result = MalwareBazaarSource().query("b" * 64, IndicatorType.HASH, ctx)
    assert result.verdict is Verdict.UNKNOWN


@respx.mock
def test_malwarebazaar_401_degrades_to_unavailable(ctx):
    # abuse.ch gating the API behind a key should show as "not run", not an error.
    respx.post("https://mb-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(401, json={"detail": "auth required"})
    )
    result = MalwareBazaarSource().query("c" * 64, IndicatorType.HASH, ctx)
    assert result.available is False
    assert result.ok is False
    assert "MALWAREBAZAAR_API_KEY" in result.summary


@respx.mock
def test_abuseipdb_high_score_is_malicious(ctx):
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json=load_fixture("abuseipdb_high.json"))
    )
    result = AbuseIpdbSource().query("185.220.101.1", IndicatorType.IP, ctx)
    assert result.verdict is Verdict.MALICIOUS
    assert result.score == 100
    assert any(p.relation is Relation.HOSTS_DOMAIN for p in result.pivots)


@respx.mock
def test_virustotal_file_malicious(ctx):
    respx.get(
        "https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f"
    ).mock(return_value=httpx.Response(200, json=load_fixture("vt_file_malicious.json")))
    result = VirusTotalSource().query(
        "44d88612fea8a8f36de82e1278abb02f", IndicatorType.HASH, ctx
    )
    assert result.verdict is Verdict.MALICIOUS
    assert result.data["malicious"] == 61
    assert result.data["threat_label"] == "trojan.eicar/test"


@respx.mock
def test_virustotal_clean_domain(ctx):
    respx.get("https://www.virustotal.com/api/v3/domains/example.com").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {
                "harmless": 70, "malicious": 0, "suspicious": 0, "undetected": 2}}}},
        )
    )
    result = VirusTotalSource().query("example.com", IndicatorType.DOMAIN, ctx)
    assert result.verdict is Verdict.CLEAN


@respx.mock
def test_virustotal_404_is_unknown(ctx):
    respx.get("https://www.virustotal.com/api/v3/domains/unknown.example").mock(
        return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}})
    )
    result = VirusTotalSource().query("unknown.example", IndicatorType.DOMAIN, ctx)
    assert result.ok is True
    assert result.verdict is Verdict.UNKNOWN


@respx.mock
def test_urlscan_collects_ip_pivots(ctx):
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={"total": 2, "results": [
                {"task": {"url": "https://example.com/", "time": "2026-01-01"},
                 "page": {"ip": "93.184.216.34", "server": "ECS"}},
                {"task": {"url": "https://example.com/x", "time": "2026-01-02"},
                 "page": {"ip": "93.184.216.34"}},
            ]},
        )
    )
    result = UrlscanSource().query("example.com", IndicatorType.DOMAIN, ctx)
    assert result.data["ips"] == ["93.184.216.34"]
    assert result.pivots[0].indicator == "93.184.216.34"


# --- DNS source: exercised via its pure result builders (no live lookups) ---

def test_dns_domain_result_builds_pivots():
    src = DnsSource()
    records = {"A": ["1.1.1.1"], "AAAA": ["::1"], "MX": ["mail.example.com"],
               "NS": ["ns1.example.com"]}
    result = src._domain_result("example.com", IndicatorType.DOMAIN, records)
    relations = {(p.indicator, p.relation) for p in result.pivots}
    assert ("1.1.1.1", Relation.RESOLVES_TO) in relations
    assert ("mail.example.com", Relation.MAIL_SERVER) in relations
    assert ("ns1.example.com", Relation.NAME_SERVER) in relations


def test_dns_ip_result_reverse():
    result = DnsSource()._ip_result("8.8.8.8", IndicatorType.IP, {"PTR": ["dns.google"]})
    assert result.pivots[0].relation is Relation.REVERSE_DNS
    assert result.pivots[0].indicator == "dns.google"
