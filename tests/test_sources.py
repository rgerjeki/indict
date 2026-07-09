"""Source tests: every HTTP source against mocked responses (respx)."""

from __future__ import annotations

import httpx
import respx
from conftest import load_fixture

from indict.models import IndicatorType, Relation, Verdict
from indict.sources.abuseipdb import AbuseIpdbSource
from indict.sources.blocklists import BlocklistSource
from indict.sources.crtsh import CrtShSource
from indict.sources.dns import DnsSource
from indict.sources.greynoise import GreyNoiseSource
from indict.sources.malwarebazaar import MalwareBazaarSource
from indict.sources.ripestat import RipeStatSource
from indict.sources.urlscan import UrlscanSource
from indict.sources.virustotal import VirusTotalSource
from indict.sources.whois import WhoisSource

_FIREHOL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
_TOR = "https://check.torproject.org/torbulkexitlist"
_SPAMHAUS = "https://www.spamhaus.org/drop/drop.txt"
_FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
_URLHAUS = "https://urlhaus.abuse.ch/downloads/text/"
_OPENPHISH = "https://openphish.com/feed.txt"


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


# --- Blocklists (keyless reputation from free feeds) ---

@respx.mock
def test_blocklists_ip_hit_is_malicious(ctx):
    respx.get(_FIREHOL).mock(return_value=httpx.Response(200, text="# level1\n185.220.101.0/24\n"))
    respx.get(_TOR).mock(return_value=httpx.Response(200, text="1.2.3.4\n"))
    respx.get(_SPAMHAUS).mock(return_value=httpx.Response(200, text="203.0.113.0/24 ; SBL1\n"))
    respx.get(_FEODO).mock(return_value=httpx.Response(200, text="# feodo\n"))

    result = BlocklistSource().query("185.220.101.1", IndicatorType.IP, ctx)
    assert result.verdict is Verdict.MALICIOUS
    assert "firehol_level1" in result.data["listed_on"]


@respx.mock
def test_blocklists_ip_miss_is_unknown_not_clean(ctx):
    for url in (_FIREHOL, _TOR, _SPAMHAUS, _FEODO):
        respx.get(url).mock(return_value=httpx.Response(200, text="# empty\n"))

    result = BlocklistSource().query("8.8.8.8", IndicatorType.IP, ctx)
    assert result.verdict is Verdict.UNKNOWN  # absence from a list is not "clean"
    assert result.data["listed_on"] == []
    assert set(result.data["checked"]) == {
        "firehol_level1", "tor_exits", "spamhaus_drop", "feodo_c2",
    }


@respx.mock
def test_blocklists_url_exact_match_is_malicious(ctx):
    respx.get(_URLHAUS).mock(
        return_value=httpx.Response(200, text="https://evil.example/x\nhttp://other.test/\n")
    )
    respx.get(_OPENPHISH).mock(return_value=httpx.Response(200, text="# none\n"))

    result = BlocklistSource().query("https://evil.example/x", IndicatorType.URL, ctx)
    assert result.verdict is Verdict.MALICIOUS
    assert "urlhaus" in result.data["listed_on"]


def test_blocklists_domain_not_flagged_by_a_url_hosted_on_it(ctx):
    # Regression: a malicious URL on github.com must not make github.com malicious.
    # Domains are not judged by URL feeds at all, so no feed applies.
    result = BlocklistSource().query("github.com", IndicatorType.DOMAIN, ctx)
    assert result.verdict is not Verdict.MALICIOUS
    assert result.available is False


@respx.mock
def test_blocklists_unavailable_when_no_feed_fetches(ctx):
    for url in (_FIREHOL, _TOR, _SPAMHAUS, _FEODO):
        respx.get(url).mock(return_value=httpx.Response(500))

    result = BlocklistSource().query("8.8.8.8", IndicatorType.IP, ctx)
    assert result.available is False


# --- RIPEstat (keyless IP enrichment) ---

@respx.mock
def test_ripestat_parses_asn_and_abuse(ctx):
    respx.get("https://stat.ripe.net/data/network-info/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"asns": ["15169"], "prefix": "8.8.8.0/24"}})
    )
    respx.get("https://stat.ripe.net/data/as-overview/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"holder": "GOOGLE, US"}})
    )
    respx.get("https://stat.ripe.net/data/abuse-contact-finder/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"abuse_contacts": ["abuse@google.com"]}})
    )

    result = RipeStatSource().query("8.8.8.8", IndicatorType.IP, ctx)
    assert result.data["asn"] == "15169"
    assert result.data["as_holder"] == "GOOGLE, US"
    assert result.data["prefix"] == "8.8.8.0/24"
    assert "abuse@google.com" in result.data["abuse_contacts"]


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
