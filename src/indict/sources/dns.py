"""DNS: the ground truth for what a domain points at right now.

For a domain we pull A/AAAA (hosting IPs), MX (mail), NS (delegation), and TXT
(SPF/verification breadcrumbs). For an IP we do the reverse (PTR) lookup. The
resolved IPs and hostnames become pivots that tie a domain to its infrastructure.

Keyless (uses your resolver via dnspython).
"""

from __future__ import annotations

import dns.resolver
import dns.reversename
from dns.exception import DNSException

from ..models import IndicatorType, Pivot, Relation, SourceResult, Verdict
from .base import Context, Source

_DOMAIN_RECORDS = ("A", "AAAA", "MX", "NS", "TXT")


class DnsSource(Source):
    name = "dns"
    supported_types = (IndicatorType.DOMAIN, IndicatorType.IP)

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        timeout = ctx.config.http_timeout
        if indicator_type is IndicatorType.DOMAIN:
            records, _ = ctx.cached(
                self.name, indicator, lambda: _resolve_domain(indicator, timeout)
            )
            return self._domain_result(indicator, indicator_type, records)  # type: ignore[arg-type]

        records, _ = ctx.cached(
            self.name, indicator, lambda: _resolve_ptr(indicator, timeout)
        )
        return self._ip_result(indicator, indicator_type, records)  # type: ignore[arg-type]

    def _domain_result(self, indicator, indicator_type, records: dict) -> SourceResult:
        pivots: list[Pivot] = []
        for ip in records.get("A", []) + records.get("AAAA", []):
            pivots.append(Pivot(ip, IndicatorType.IP, Relation.RESOLVES_TO, self.name))
        for mx in records.get("MX", []):
            pivots.append(Pivot(mx, IndicatorType.DOMAIN, Relation.MAIL_SERVER, self.name))
        for ns in records.get("NS", []):
            pivots.append(Pivot(ns, IndicatorType.DOMAIN, Relation.NAME_SERVER, self.name))

        a_count = len(records.get("A", [])) + len(records.get("AAAA", []))
        summary = (
            f"resolves to {a_count} IP(s); "
            f"{len(records.get('NS', []))} nameserver(s), "
            f"{len(records.get('MX', []))} mail host(s)"
            if a_count
            else "no A/AAAA records (does not currently resolve)"
        )
        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=Verdict.UNKNOWN,
            summary=summary,
            data=records,
            pivots=pivots,
        )

    def _ip_result(self, indicator, indicator_type, records: dict) -> SourceResult:
        ptr = records.get("PTR", [])
        pivots = [
            Pivot(host, IndicatorType.DOMAIN, Relation.REVERSE_DNS, self.name)
            for host in ptr
        ]
        summary = f"reverse DNS: {', '.join(ptr)}" if ptr else "no reverse DNS (PTR) record"
        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=Verdict.UNKNOWN,
            summary=summary,
            data=records,
            pivots=pivots,
        )


def _resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    return resolver


def _resolve_domain(domain: str, timeout: float) -> dict[str, list[str]]:
    resolver = _resolver(timeout)
    records: dict[str, list[str]] = {}
    for rtype in _DOMAIN_RECORDS:
        try:
            answers = resolver.resolve(domain, rtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, DNSException):
            continue
        if rtype == "MX":
            values = sorted(str(r.exchange).rstrip(".").lower() for r in answers)
        elif rtype in ("NS",):
            values = sorted(str(r.target).rstrip(".").lower() for r in answers)
        elif rtype == "TXT":
            values = [b"".join(r.strings).decode("utf-8", "replace") for r in answers]
        else:  # A / AAAA
            values = sorted(str(r) for r in answers)
        if values:
            records[rtype] = values
    return records


def _resolve_ptr(ip: str, timeout: float) -> dict[str, list[str]]:
    resolver = _resolver(timeout)
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, "PTR")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, DNSException, ValueError):
        return {}
    return {"PTR": sorted(str(r).rstrip(".").lower() for r in answers)}
