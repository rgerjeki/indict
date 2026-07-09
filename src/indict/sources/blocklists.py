"""Free threat blocklists: keyless reputation.

The other keyless sources return facts (DNS, WHOIS, subdomains). This one returns a
verdict, without any API key, by checking the indicator against a handful of free,
downloadable reputation feeds. Being listed on FireHOL or Feodo Tracker is a real
malicious signal; being a Tor exit is worth noting.

One honesty rule baked in: absence from a blocklist is not a clean bill of health,
so a miss reports `unknown`, never `clean`. Keyless, this lets you confirm bad, not
confirm good.

Feed URLs drift over time and some (abuse.ch) may start requiring a free account.
Any feed we cannot fetch is reported as skipped rather than failing the source.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from ..models import IndicatorType, SourceResult, Verdict
from .base import Context, Source


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    kind: str  # "ip" or "url"
    verdict: Verdict  # what a hit on this feed means
    note: str
    abusech: bool = False  # abuse.ch feeds may want a free Auth-Key


FEEDS: tuple[Feed, ...] = (
    Feed(
        "firehol_level1",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "ip", Verdict.MALICIOUS, "aggregated known-malicious IPs (FireHOL level 1)",
    ),
    Feed(
        "tor_exits",
        "https://check.torproject.org/torbulkexitlist",
        "ip", Verdict.SUSPICIOUS, "Tor exit node",
    ),
    Feed(
        "spamhaus_drop",
        "https://www.spamhaus.org/drop/drop.txt",
        "ip", Verdict.MALICIOUS, "Spamhaus DROP (hijacked or malicious netblock)",
    ),
    Feed(
        "feodo_c2",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "ip", Verdict.MALICIOUS, "Feodo Tracker botnet C2", abusech=True,
    ),
    Feed(
        "urlhaus",
        "https://urlhaus.abuse.ch/downloads/text/",
        "url", Verdict.MALICIOUS, "URLhaus malicious URL", abusech=True,
    ),
    Feed(
        "openphish",
        "https://openphish.com/feed.txt",
        "url", Verdict.MALICIOUS, "OpenPhish phishing URL",
    ),
)

_SEVERITY = {Verdict.MALICIOUS: 3, Verdict.SUSPICIOUS: 2, Verdict.CLEAN: 1, Verdict.UNKNOWN: 0}


class BlocklistSource(Source):
    name = "blocklists"
    # IPs are matched against IP feeds; URLs against URL feeds by exact URL.
    # Bare domains are deliberately NOT judged here: a URL feed listing one bad
    # URL hosted on a domain (github.com, pastebin, a CDN) does not make the whole
    # domain malicious. Domain-level reputation would need a domain feed.
    supported_types = (IndicatorType.IP, IndicatorType.URL)

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        feeds = [f for f in FEEDS if _applies(f, indicator_type)]

        checked: list[str] = []
        skipped: list[str] = []
        hits: list[Feed] = []

        for feed in feeds:
            headers = _abusech_headers(feed, ctx)
            text = ctx.feeds.get_text(feed.name, feed.url, headers)
            if text is None:
                skipped.append(feed.name)
                continue
            checked.append(feed.name)
            if _matches(feed, indicator, indicator_type, text):
                hits.append(feed)

        if not checked:
            return SourceResult.unavailable(
                self.name, indicator, indicator_type,
                "could not fetch any blocklist feed",
            )

        if hits:
            verdict = max((h.verdict for h in hits), key=lambda v: _SEVERITY[v])
            summary = f"listed on {len(hits)} of {len(checked)} blocklist(s): " + ", ".join(
                h.note for h in hits
            )
        else:
            verdict = Verdict.UNKNOWN
            summary = f"not listed on {len(checked)} blocklist(s) checked"

        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            summary=summary,
            data={
                "listed_on": [h.name for h in hits],
                "checked": checked,
                "skipped": skipped,
            },
        )


def _applies(feed: Feed, indicator_type: IndicatorType) -> bool:
    if indicator_type is IndicatorType.IP:
        return feed.kind == "ip"
    if indicator_type is IndicatorType.URL:
        return feed.kind == "url"
    return False


def _abusech_headers(feed: Feed, ctx: Context) -> dict[str, str]:
    import os

    if feed.abusech and (key := os.getenv("MALWAREBAZAAR_API_KEY")):
        return {"Auth-Key": key}
    return {}


def _matches(feed: Feed, indicator: str, indicator_type: IndicatorType, text: str) -> bool:
    if feed.kind == "ip":
        return _ip_listed(indicator, text)
    return _url_listed(indicator, text)


def _ip_listed(ip_str: str, text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for line in text.splitlines():
        token = _first_token(line)
        if not token:
            continue
        try:
            if "/" in token:
                if ip in ipaddress.ip_network(token, strict=False):
                    return True
            elif ipaddress.ip_address(token) == ip:
                return True
        except ValueError:
            continue
    return False


def _url_listed(url: str, text: str) -> bool:
    """Match a URL against a URL feed by exact URL (ignoring a trailing slash).

    Deliberately not host-based: we only call a URL malicious if that exact URL is
    listed, not because something else on the same host is.
    """
    target = url.rstrip("/")
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.rstrip("/") == target:
            return True
    return False


def _first_token(line: str) -> str:
    """First IP/CIDR token on a line, skipping comments (# and ;)."""
    line = line.strip()
    if not line or line[0] in "#;":
        return ""
    return re.split(r"[\s;]", line, maxsplit=1)[0]
