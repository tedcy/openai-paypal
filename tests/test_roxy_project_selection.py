from datetime import datetime, timezone

import pytest

from config import BROWSER_PROFILE
from paypal.country import browser_profile_for, profile_for_country
from paypal.roxy_fingerprint import (
    RoxyApiClient,
    RoxyFingerprintError,
    load_roxy_capture_config,
    roxy_language_value,
    roxy_timezone_value,
)


@pytest.mark.parametrize(
    ("country", "expected"),
    [
        ("BR", "GMT-03:00 America/Sao_Paulo"),
        ("TH", "GMT+07:00 Asia/Bangkok"),
        ("BA", "GMT+01:00 Europe/Sarajevo"),
        ("US", "GMT-06:00 America/Chicago"),
    ],
)
def test_roxy_timezone_uses_canonical_appendix_value(
    country: str, expected: str,
) -> None:
    profile = browser_profile_for(
        profile_for_country(country),
        BROWSER_PROFILE,
        when=datetime(2026, 7, 29, tzinfo=timezone.utc),
    )

    assert roxy_timezone_value(profile) == expected
    assert load_roxy_capture_config(browser_profile=profile).timezone == expected


def test_roxy_timezone_does_not_use_dst_offset_in_appendix_value() -> None:
    profile = browser_profile_for(
        profile_for_country("US"),
        BROWSER_PROFILE,
        when=datetime(2026, 7, 29, tzinfo=timezone.utc),
    )

    assert profile["timezone_offset_minutes"] == 300
    assert roxy_timezone_value(profile) == "GMT-06:00 America/Chicago"


def test_ba_roxy_language_uses_supported_ui_value_without_changing_profile() -> None:
    profile = browser_profile_for(profile_for_country("BA"), BROWSER_PROFILE)

    assert profile["language"] == "en-BA"
    assert roxy_language_value(profile) == "en-US"
    assert load_roxy_capture_config(browser_profile=profile).language == "en-US"


def test_roxy_timezone_rejects_unsupported_profile_timezone() -> None:
    with pytest.raises(RoxyFingerprintError, match="no configured appendix timezone"):
        roxy_timezone_value({"timezone": "America/New_York"})


def test_quota_fallback_does_not_reuse_profile_from_another_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = RoxyApiClient.__new__(RoxyApiClient)
    monkeypatch.setattr(
        client,
        "create_profile",
        lambda workspace_id, project_id: (_ for _ in ()).throw(
            RoxyFingerprintError("窗口额度不足")
        ),
    )
    monkeypatch.setattr(client, "cleanup_paypal_auto_profiles", lambda workspace_id: 0)
    monkeypatch.setattr(
        client,
        "list_profiles",
        lambda workspace_id: [
            {
                "dirId": "gpt-profile",
                "projectId": 149639,
            }
        ],
    )

    with pytest.raises(RoxyFingerprintError, match=r"project 148735.*无可复用"):
        client.create_or_reuse_profile(108643, 148735)


def test_quota_fallback_reuses_profile_from_selected_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = RoxyApiClient.__new__(RoxyApiClient)
    monkeypatch.setattr(
        client,
        "create_profile",
        lambda workspace_id, project_id: (_ for _ in ()).throw(
            RoxyFingerprintError("窗口额度不足")
        ),
    )
    monkeypatch.setattr(client, "cleanup_paypal_auto_profiles", lambda workspace_id: 0)
    monkeypatch.setattr(
        client,
        "list_profiles",
        lambda workspace_id: [
            {"dirId": "gpt-profile", "projectId": 149639},
            {"dirId": "pp-profile", "projectId": 148735},
        ],
    )

    assert client.create_or_reuse_profile(108643, 148735) == "pp-profile"
