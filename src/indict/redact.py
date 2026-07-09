"""PII redaction for shareable output.

WHOIS/RDAP records in particular carry registrant names, emails, phones, and
addresses. `--redact` strips them so a report can be pasted into a ticket or a
screenshot without leaking a person's details. We redact by known field name and
by pattern (emails anywhere), and mark the report as redacted.
"""

from __future__ import annotations

import re
from typing import Any

from .models import Report

REDACTED = "[redacted]"

# Field names (case-insensitive substrings) whose values are treated as PII.
_PII_KEY_HINTS = (
    "name",
    "email",
    "phone",
    "fax",
    "address",
    "street",
    "city",
    "postal",
    "zip",
    "registrant",
    "admin",
    "tech",
    "contact",
    "org",
)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Keys we never redact even though they contain a hint substring, because they
# are infrastructure, not people.
_ALLOW_KEYS = {"name_servers", "nameservers", "organization_asn"}


def _is_pii_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _ALLOW_KEYS:
        return False
    return any(hint in lowered for hint in _PII_KEY_HINTS)


def _scrub(value: Any, parent_is_pii: bool = False) -> Any:
    if isinstance(value, dict):
        return {
            k: _scrub(v, parent_is_pii=parent_is_pii or _is_pii_key(k))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub(v, parent_is_pii=parent_is_pii) for v in value]
    if isinstance(value, str):
        if parent_is_pii:
            return REDACTED
        return _EMAIL_RE.sub(REDACTED, value)
    return value


def redact_report(report: Report) -> Report:
    """Redact PII in place across every source result, then flag the report."""
    for result in report.results:
        result.data = _scrub(result.data)  # type: ignore[assignment]
        result.summary = _EMAIL_RE.sub(REDACTED, result.summary)
    report.evidence = [_EMAIL_RE.sub(REDACTED, e) for e in report.evidence]
    report.redacted = True
    return report
