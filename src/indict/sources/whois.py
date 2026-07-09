"""WHOIS via RDAP.

RDAP is the modern, JSON replacement for port-43 WHOIS, and rdap.org bootstraps
to the right registry for us. For a domain we pull registrar, registration date,
and nameservers; for an IP we pull the network name, org, and country. A very
young domain is a soft suspicious signal (fresh registrations are a phishing
staple), so we surface age.

Registrant name/email are PII and land under a `registrant` key so `--redact`
can strip them. Keyless.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..models import IndicatorType, Pivot, Relation, SourceResult, Verdict
from .base import Context, Source

_YOUNG_DOMAIN_DAYS = 30


class WhoisSource(Source):
    name = "whois"
    supported_types = (IndicatorType.DOMAIN, IndicatorType.IP)

    def query(self, indicator: str, indicator_type: IndicatorType, ctx: Context) -> SourceResult:
        kind = "domain" if indicator_type is IndicatorType.DOMAIN else "ip"
        url = f"https://rdap.org/{kind}/{indicator}"
        payload, from_cache = ctx.cached(
            self.name, indicator, lambda: ctx.http.get_json(url)
        )
        if indicator_type is IndicatorType.DOMAIN:
            return self._domain_result(indicator, indicator_type, payload, from_cache)
        return self._ip_result(indicator, indicator_type, payload, from_cache)

    def _domain_result(self, indicator, indicator_type, payload, from_cache) -> SourceResult:
        registrar = _entity_name(payload, "registrar")
        created = _event_date(payload, "registration")
        expires = _event_date(payload, "expiration")
        nameservers = sorted(
            ns.get("ldhName", "").lower()
            for ns in payload.get("nameservers", [])
            if ns.get("ldhName")
        )
        registrant = _registrant(payload)

        age_days = _age_days(created)
        verdict = Verdict.UNKNOWN
        notes = []
        if age_days is not None and age_days < _YOUNG_DOMAIN_DAYS:
            verdict = Verdict.SUSPICIOUS
            notes.append(f"registered {age_days} day(s) ago")

        pivots = [
            Pivot(ns, IndicatorType.DOMAIN, Relation.NAME_SERVER, self.name)
            for ns in nameservers
        ]
        summary = ", ".join(
            part
            for part in (
                f"registrar {registrar}" if registrar else "",
                f"created {created}" if created else "",
                *notes,
            )
            if part
        ) or "RDAP record found"

        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            summary=summary,
            data={
                "registrar": registrar,
                "created": created,
                "expires": expires,
                "age_days": age_days,
                "name_servers": nameservers,
                "registrant": registrant,
            },
            links=[f"https://rdap.org/domain/{indicator}"],
            pivots=pivots,
            from_cache=from_cache,
        )

    def _ip_result(self, indicator, indicator_type, payload, from_cache) -> SourceResult:
        network_name = payload.get("name")
        country = payload.get("country")
        org = _entity_name(payload, "registrant") or _entity_name(payload, "administrative")
        cidr = _cidr(payload)
        summary = ", ".join(
            part
            for part in (
                f"network {network_name}" if network_name else "",
                f"org {org}" if org else "",
                f"country {country}" if country else "",
            )
            if part
        ) or "RDAP record found"

        return SourceResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=Verdict.UNKNOWN,
            summary=summary,
            data={
                "network_name": network_name,
                "organization": org,
                "country": country,
                "cidr": cidr,
            },
            links=[f"https://rdap.org/ip/{indicator}"],
            from_cache=from_cache,
        )


def _entities(payload: dict, role: str) -> list[dict]:
    return [
        e for e in payload.get("entities", [])
        if isinstance(e, dict) and role in (e.get("roles") or [])
    ]


def _vcard_get(entity: dict, field: str) -> str | None:
    """Pull a field (fn, email, ...) out of an RDAP jCard/vCard array."""
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == field:
            return item[-1] if isinstance(item[-1], str) else None
    return None


def _entity_name(payload: dict, role: str) -> str | None:
    for entity in _entities(payload, role):
        name = _vcard_get(entity, "fn") or entity.get("handle")
        if name:
            return name
    return None


def _registrant(payload: dict) -> dict[str, str | None]:
    for entity in _entities(payload, "registrant"):
        return {
            "name": _vcard_get(entity, "fn"),
            "email": _vcard_get(entity, "email"),
            "organization": _vcard_get(entity, "org"),
        }
    return {}


def _event_date(payload: dict, action: str) -> str | None:
    for event in payload.get("events", []):
        if isinstance(event, dict) and event.get("eventAction") == action:
            return event.get("eventDate")
    return None


def _age_days(created: str | None) -> int | None:
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (datetime.now(UTC) - dt).days


def _cidr(payload: dict) -> str | None:
    for entry in payload.get("cidr0_cidrs", []):
        if isinstance(entry, dict):
            prefix = entry.get("v4prefix") or entry.get("v6prefix")
            length = entry.get("length")
            if prefix and length is not None:
                return f"{prefix}/{length}"
    return None
