"""Country and input normalization for the CTF agreement flow.

The checkout flow deliberately supports only the four country profiles used
by the authorized CTF environment.  Keeping this in one module prevents phone,
locale and timezone decisions from drifting across the CLI, Web UI and flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Mapping
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo


_E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")
_BA_TOKEN_RE = re.compile(r"^BA-[A-Za-z0-9]{8,80}$")
_APPROVAL_HOSTS = {"paypal.com", "www.paypal.com"}


@dataclass(frozen=True, slots=True)
class CountryProfile:
    country: str
    dial_prefix: str
    locale: str
    language: str
    graphql_language: str
    timezone: str
    address_mode: str


COUNTRY_PROFILES: dict[str, CountryProfile] = {
    "BR": CountryProfile(
        country="BR",
        dial_prefix="+55",
        locale="pt_BR",
        language="pt-BR",
        graphql_language="pt",
        timezone="America/Sao_Paulo",
        address_mode="AUTOCOMPLETE",
    ),
    "TH": CountryProfile(
        country="TH",
        dial_prefix="+66",
        locale="en_GB",
        language="en-TH",
        graphql_language="en",
        timezone="Asia/Bangkok",
        address_mode="MANUAL",
    ),
    "BA": CountryProfile(
        country="BA",
        dial_prefix="+387",
        locale="en_US",
        language="en-BA",
        graphql_language="en",
        timezone="Europe/Sarajevo",
        address_mode="MANUAL",
    ),
    "US": CountryProfile(
        country="US",
        dial_prefix="+1",
        locale="en_US",
        language="en-US",
        graphql_language="en",
        timezone="America/Chicago",
        address_mode="MANUAL",
    ),
}


def profile_for_country(country: str) -> CountryProfile:
    key = (country or "").strip().upper()
    try:
        return COUNTRY_PROFILES[key]
    except KeyError as exc:
        raise ValueError(
            f"unsupported country: {country!r}; expected BR, TH, BA or US"
        ) from exc


def normalize_e164_phone(phone: str) -> str:
    value = (phone or "").strip()
    if not _E164_RE.fullmatch(value):
        raise ValueError("phone must use E.164 format, for example +5591999999999")
    return value


def profile_for_phone(phone: str) -> CountryProfile:
    value = normalize_e164_phone(phone)
    # Check the longest prefix first even though the current prefixes do not
    # overlap.  This keeps the routing correct if another profile is added.
    for profile in sorted(
        COUNTRY_PROFILES.values(),
        key=lambda item: len(item.dial_prefix),
        reverse=True,
    ):
        if value.startswith(profile.dial_prefix):
            local = value[len(profile.dial_prefix) :]
            if len(local) < 6:
                break
            return profile
    raise ValueError(
        "unsupported phone country prefix; expected +55, +66, +387 or +1"
    )


def phone_parts(phone: str, expected: CountryProfile | None = None) -> tuple[str, str, CountryProfile]:
    value = normalize_e164_phone(phone)
    profile = profile_for_phone(value)
    if expected is not None and profile.country != expected.country:
        raise ValueError(
            f"phone country cannot change during a task ({expected.country} -> {profile.country}); "
            "start a new task instead"
        )
    local = value[len(profile.dial_prefix) :]
    return value, local, profile


def parse_ba_token(value: str) -> str:
    """Accept a raw BA token or an agreements/approve URL and return the token."""
    raw = (value or "").strip()
    if _BA_TOKEN_RE.fullmatch(raw):
        return raw

    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise ValueError("BA Token or approval URL is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("expected BA-... or a full agreements/approve URL")
    if (parsed.hostname or "").lower().rstrip(".") not in _APPROVAL_HOSTS:
        raise ValueError("approval URL host must be paypal.com or www.paypal.com")
    if parsed.path.rstrip("/") != "/agreements/approve":
        raise ValueError("approval URL path must be /agreements/approve")
    values = parse_qs(parsed.query, keep_blank_values=True).get("ba_token", [])
    if len(values) != 1 or not _BA_TOKEN_RE.fullmatch(values[0]):
        raise ValueError("approval URL must contain exactly one valid ba_token")
    return values[0]


def accept_language_value(language: str) -> str:
    """Build a browser-like Accept-Language value without regional leakage."""
    selected = (language or "en-US").strip() or "en-US"
    root = selected.split("-", 1)[0]
    ordered = [selected, root, "en-US", "en"]
    unique: list[str] = []
    seen: set[str] = set()
    for item in ordered:
        key = item.lower()
        if item and key not in seen:
            seen.add(key)
            unique.append(item)
    weights = (None, 0.9, 0.8, 0.7)
    return ",".join(
        item if weights[index] is None else f"{item};q={weights[index]:.1f}"
        for index, item in enumerate(unique)
    )


def timezone_values(
    profile: CountryProfile,
    when: datetime | None = None,
) -> tuple[int, bool]:
    """Return JavaScript getTimezoneOffset minutes and DST state."""
    instant = when or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    local = instant.astimezone(ZoneInfo(profile.timezone))
    utc_offset = local.utcoffset()
    offset_minutes = -int((utc_offset.total_seconds() if utc_offset else 0) // 60)
    dst_delta = local.dst()
    return offset_minutes, bool(dst_delta and dst_delta.total_seconds())


def browser_profile_for(
    profile: CountryProfile,
    base: Mapping[str, object] | None = None,
    *,
    when: datetime | None = None,
) -> dict[str, object]:
    result = dict(base or {})
    offset_minutes, dst = timezone_values(profile, when)
    language_root = profile.language.split("-", 1)[0]
    languages = list(
        dict.fromkeys((profile.language, language_root, "en-US", "en"))
    )
    result.update(
        {
            "country": profile.country,
            "language": profile.language,
            "languages": languages,
            "locale": profile.locale,
            "graphql_language": profile.graphql_language,
            "timezone": profile.timezone,
            "timezone_offset_minutes": offset_minutes,
            "timezone_offset_ms": offset_minutes * 60 * 1000,
            "dst": dst,
        }
    )
    return result
