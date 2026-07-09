"""indict: OSINT indicator enrichment and triage.

Given a single indicator (IPv4, domain, file hash, or URL), indict detects its
type, queries multiple OSINT sources, normalizes their very different responses
into one consistent shape, correlates and pivots to related infrastructure, and
prints a readable report plus an aggregated verdict.
"""

__version__ = "0.1.0"
