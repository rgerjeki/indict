"""Indicator type detection and validation.

The first thing the tool does with user input: figure out whether it is an IP, a
domain, a file hash, or a URL, and normalize it. We also refang defanged input
(hxxp://evil[.]com) so analysts can paste straight from a report.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .models import IndicatorType

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")

# A pragmatic domain matcher: labels of letters/digits/hyphens, a real TLD of at
# least two letters. Not a full RFC validator, but it keeps obvious junk out.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
)


class DetectionError(ValueError):
    """Raised when an input cannot be classified as a supported indicator."""


def refang(value: str) -> str:
    """Undo common defanging so pasted indicators parse cleanly."""
    v = value.strip().strip("'\"")
    replacements = {
        "hxxps": "https",
        "hxxp": "http",
        "fxp": "ftp",
        "[.]": ".",
        "(.)": ".",
        "{.}": ".",
        "[dot]": ".",
        " dot ": ".",
        "[:]": ":",
        "[//]": "//",
        "[@]": "@",
        "[at]": "@",
    }
    for needle, repl in replacements.items():
        v = v.replace(needle, repl)
    return v.strip()


def _hash_kind(value: str) -> str | None:
    if _HEX_RE.match(value):
        return _HASH_LENGTHS.get(len(value))
    return None


def detect(value: str) -> tuple[IndicatorType, str]:
    """Classify and normalize an indicator.

    Returns the detected type and a normalized string (lowercased host, refanged,
    etc.). Order matters: URLs carry a scheme, IPs and hashes are unambiguous, and
    a domain is the fallback that must still pass validation.

    Raises DetectionError for anything we cannot confidently classify.
    """
    raw = refang(value)
    if not raw:
        raise DetectionError("empty indicator")

    # URL: has a scheme like http(s):// or ftp://
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        parts = urlsplit(raw)
        if not parts.netloc:
            raise DetectionError(f"looks like a URL but has no host: {value!r}")
        # Normalize scheme and host to lowercase, keep path/query as-is.
        normalized = parts._replace(
            scheme=parts.scheme.lower(),
            netloc=parts.netloc.lower(),
        ).geturl()
        return IndicatorType.URL, normalized

    # IP address (v4 or v6). We accept v6 for detection even though most sources
    # in v1 are v4-oriented; sources decide what they support.
    try:
        ip = ipaddress.ip_address(raw)
        return IndicatorType.IP, str(ip)
    except ValueError:
        pass

    # File hash (md5 / sha1 / sha256 by length).
    if _hash_kind(raw):
        return IndicatorType.HASH, raw.lower()

    # Domain (fallback). Strip a trailing dot and a leading wildcard.
    candidate = raw.rstrip(".").lower()
    candidate = candidate.removeprefix("*.")
    if _DOMAIN_RE.match(candidate):
        return IndicatorType.DOMAIN, candidate

    raise DetectionError(
        f"could not classify {value!r} as an ip, domain, hash, or url"
    )


def hash_kind(value: str) -> str | None:
    """Public helper: which hash algorithm a value looks like, or None."""
    return _hash_kind(value.strip().lower())


def host_of(url: str) -> str | None:
    """Extract the hostname from a URL, lowercased, or None."""
    host = urlsplit(url).hostname
    return host.lower() if host else None
