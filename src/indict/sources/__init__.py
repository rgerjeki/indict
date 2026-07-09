"""Source registry.

`all_sources()` returns one instance of every source. The orchestrator asks each
whether it supports the indicator type and whether it is available (keyless ones
always are; keyed ones need their key), so adding a source is just: write the
module and add it to this list.
"""

from __future__ import annotations

from .abuseipdb import AbuseIpdbSource
from .base import Context, Source
from .blocklists import BlocklistSource
from .crtsh import CrtShSource
from .dns import DnsSource
from .greynoise import GreyNoiseSource
from .malwarebazaar import MalwareBazaarSource
from .ripestat import RipeStatSource
from .urlscan import UrlscanSource
from .virustotal import VirusTotalSource
from .whois import WhoisSource

__all__ = ["Context", "Source", "all_sources"]


def all_sources() -> list[Source]:
    return [
        # Keyless
        DnsSource(),
        WhoisSource(),
        RipeStatSource(),
        CrtShSource(),
        GreyNoiseSource(),
        BlocklistSource(),
        MalwareBazaarSource(),
        UrlscanSource(),
        # Keyed (graceful degradation without a key)
        AbuseIpdbSource(),
        VirusTotalSource(),
    ]
