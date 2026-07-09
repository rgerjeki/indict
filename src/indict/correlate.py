"""Correlation: turn one indicator into a picture of related infrastructure.

Enrichment gives you facts from each source in isolation. Correlation is the
analyst move: take the pivots every source produced (subdomains, resolved IPs,
reverse-DNS names) and cluster them so you can see, for example, that fifteen
subdomains all sit on the same hosting IP. That clustering is what a raw dump of
six API responses will not give you.

Subdomain resolution is injected (`resolve`) so the CLI can wire in live DNS while
tests stay hermetic.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from .models import Cluster, IndicatorType, Pivot, Relation, Report

Resolver = Callable[[str], list[str]]

# Resolving every subdomain a busy domain has is slow and noisy; cap it.
_MAX_RESOLVE = 25


def correlate(report: Report, resolve: Resolver | None = None) -> Report:
    """Populate `report.pivots` (deduped) and `report.clusters`."""
    report.pivots = _dedupe_pivots(report)

    if report.indicator_type is IndicatorType.DOMAIN:
        report.clusters = _cluster_domain(report, resolve)
    elif report.indicator_type is IndicatorType.IP:
        report.clusters = _cluster_ip(report)
    elif report.indicator_type is IndicatorType.URL:
        report.clusters = _cluster_url(report)
    return report


def _dedupe_pivots(report: Report) -> list[Pivot]:
    """Flatten every source's pivots, drop the primary indicator and dupes."""
    seen: set[tuple[str, str]] = set()
    pivots: list[Pivot] = []
    for result in report.results:
        for pivot in result.pivots:
            if pivot.indicator == report.indicator:
                continue
            key = (pivot.indicator, pivot.relation.value)
            if key in seen:
                continue
            seen.add(key)
            pivots.append(pivot)
    return pivots


def _cluster_domain(report: Report, resolve: Resolver | None) -> list[Cluster]:
    """Cluster the domain and its subdomains by the IP they resolve to."""
    by_ip: dict[str, set[str]] = defaultdict(set)

    # IPs the apex already resolved to (from DNS / VirusTotal pivots).
    for pivot in report.pivots:
        if pivot.relation is Relation.RESOLVES_TO and pivot.indicator_type is IndicatorType.IP:
            by_ip[pivot.indicator].add(report.indicator)

    subdomains = sorted(
        p.indicator for p in report.pivots if p.relation is Relation.SUBDOMAIN
    )
    if resolve:
        for host in subdomains[:_MAX_RESOLVE]:
            for ip in resolve(host):
                by_ip[ip].add(host)

    return _clusters_from_map(by_ip, "hosting IP")


def _cluster_ip(report: Report) -> list[Cluster]:
    """Cluster the domains that point at (or name) this IP."""
    domains = sorted(
        {
            p.indicator
            for p in report.pivots
            if p.indicator_type is IndicatorType.DOMAIN
            and p.relation in (Relation.REVERSE_DNS, Relation.HOSTS_DOMAIN)
        }
    )
    if not domains:
        return []
    return [Cluster(key=report.indicator, label="domains on this IP", members=domains)]


def _cluster_url(report: Report) -> list[Cluster]:
    """Cluster the IPs a URL's host has served from."""
    ips = sorted(
        {
            p.indicator
            for p in report.pivots
            if p.indicator_type is IndicatorType.IP
            and p.relation is Relation.RESOLVES_TO
        }
    )
    if not ips:
        return []
    return [Cluster(key=report.indicator, label="serving IPs", members=ips)]


def _clusters_from_map(by_ip: dict[str, set[str]], label: str) -> list[Cluster]:
    clusters = [
        Cluster(key=ip, label=label, members=sorted(members))
        for ip, members in by_ip.items()
        if members
    ]
    # Biggest clusters first: the shared-hosting story is the interesting one.
    clusters.sort(key=lambda c: (-len(c.members), c.key))
    return clusters
