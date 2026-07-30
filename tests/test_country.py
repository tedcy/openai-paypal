from datetime import datetime, timezone

import pytest

from paypal.country import (
    accept_language_value,
    browser_profile_for,
    parse_ba_token,
    phone_parts,
    profile_for_country,
    profile_for_phone,
    timezone_values,
)


@pytest.mark.parametrize(
    ("phone", "country"),
    [
        ("+5500000000000", "BR"),
        ("+66000000000", "TH"),
        ("+38700000000", "BA"),
        ("+12025550123", "US"),
    ],
)
def test_phone_routes_to_country(phone: str, country: str) -> None:
    assert profile_for_phone(phone).country == country


@pytest.mark.parametrize(
    "phone",
    ["5511999999999", "+33123456789", "+012345678", "+55 11999999999", ""],
)
def test_phone_requires_supported_e164(phone: str) -> None:
    with pytest.raises(ValueError):
        profile_for_phone(phone)


def test_phone_change_must_stay_in_country() -> None:
    expected = profile_for_country("TH")
    full, local, selected = phone_parts("+66000000001", expected=expected)
    assert (full, local, selected.country) == ("+66000000001", "000000001", "TH")
    with pytest.raises(ValueError, match="cannot change"):
        phone_parts("+38700000000", expected=expected)


def test_us_phone_change_stays_us_and_rejects_cross_country() -> None:
    expected = profile_for_country("US")
    full, local, selected = phone_parts("+13125550124", expected=expected)
    assert (full, local, selected.country) == ("+13125550124", "3125550124", "US")
    with pytest.raises(ValueError, match="cannot change"):
        phone_parts("+5500000000000", expected=expected)


def test_ba_token_accepts_raw_or_approval_url() -> None:
    token = "BA-TESTTOKEN123456"
    assert parse_ba_token(token) == token
    assert parse_ba_token(
        f"https://www.paypal.com/agreements/approve?ba_token={token}"
    ) == token


@pytest.mark.parametrize(
    "value",
    [
        "EC-TESTTOKEN123456",
        "https://www.paypal.com/pay?ba_token=BA-TESTTOKEN123456",
        "https://www.paypal.com/agreements/approve",
        "https://www.paypal.com/agreements/approve?ba_token=bad",
    ],
)
def test_ba_token_rejects_invalid_input(value: str) -> None:
    with pytest.raises(ValueError):
        parse_ba_token(value)


def test_ba_token_rejects_non_paypal_approval_host() -> None:
    with pytest.raises(ValueError, match="host"):
        parse_ba_token(
            "https://example.test/agreements/approve?ba_token=BA-TESTTOKEN123456"
        )


@pytest.mark.parametrize(
    ("language", "expected"),
    [
        ("pt-BR", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"),
        ("en-TH", "en-TH,en;q=0.9,en-US;q=0.8"),
        ("en-BA", "en-BA,en;q=0.9,en-US;q=0.8"),
        ("en-US", "en-US,en;q=0.9"),
    ],
)
def test_accept_language_has_no_brazilian_leakage(language: str, expected: str) -> None:
    assert accept_language_value(language) == expected


def test_timezone_offsets_and_dst() -> None:
    winter = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
    summer = datetime(2026, 7, 15, 12, tzinfo=timezone.utc)
    assert timezone_values(profile_for_country("BR"), winter) == (180, False)
    assert timezone_values(profile_for_country("TH"), winter) == (-420, False)
    assert timezone_values(profile_for_country("BA"), winter) == (-60, False)
    assert timezone_values(profile_for_country("BA"), summer) == (-120, True)
    assert timezone_values(profile_for_country("US"), winter) == (360, False)
    assert timezone_values(profile_for_country("US"), summer) == (300, True)


def test_browser_profile_contains_graphql_and_timezone_values() -> None:
    profile = browser_profile_for(
        profile_for_country("BA"),
        {"chrome_major": 150},
        when=datetime(2026, 7, 15, 12, tzinfo=timezone.utc),
    )
    assert profile["country"] == "BA"
    assert profile["locale"] == "en_US"
    assert profile["language"] == "en-BA"
    assert profile["languages"] == ["en-BA", "en", "en-US"]
    assert profile["graphql_language"] == "en"
    assert profile["timezone"] == "Europe/Sarajevo"
    assert profile["timezone_offset_minutes"] == -120
    assert profile["timezone_offset_ms"] == -7_200_000
    assert profile["dst"] is True


def test_us_browser_profile_uses_chicago_locale_and_dst() -> None:
    profile = browser_profile_for(
        profile_for_country("US"),
        {"chrome_major": 150},
        when=datetime(2026, 7, 15, 12, tzinfo=timezone.utc),
    )
    assert profile["country"] == "US"
    assert profile["locale"] == "en_US"
    assert profile["language"] == "en-US"
    assert profile["languages"] == ["en-US", "en"]
    assert profile["graphql_language"] == "en"
    assert profile["timezone"] == "America/Chicago"
    assert profile["timezone_offset_minutes"] == 300
    assert profile["timezone_offset_ms"] == 18_000_000
    assert profile["dst"] is True
