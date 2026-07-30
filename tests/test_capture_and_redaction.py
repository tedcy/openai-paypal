import json

import httpx

from paypal.session import sanitize_for_log
from paypal.local_headless import _redact_debug_event, headless_optimized_raw_debug_enabled
from paypal.traffic_recorder import TrafficRecorder, redact
from paypal.flow import _cookie_name_summary, _diagnostic_url, _challenge_markers


def test_risk_diagnostic_helpers_expose_names_only() -> None:
    summary = _cookie_name_summary([
        {"name": "datadome", "value": "COOKIE-SECRET"},
        {"name": "nsid", "value": "SESSION-SECRET"},
    ])
    assert summary == {"count": 2, "names": ["datadome", "nsid"]}
    assert "COOKIE-SECRET" not in json.dumps(summary)
    assert _diagnostic_url("https://www.paypal.com/graphql?ba_token=BA-SECRET&ec_token=EC-SECRET") == "https://www.paypal.com/graphql"
    assert _challenge_markers("DataDome authchallenge recaptcha") == ["authchallenge", "recaptcha", "datadome"]


def test_runtime_and_traffic_redaction_cover_sensitive_fields() -> None:
    value = {
        "otp": "123456",
        "phone": "+38700000000",
        "email": "person@example.test",
        "cardNumber": "4147091234567890",
        "accessToken": "ACCESS-SECRET-TOKEN",
        "cookie": "session=secret",
    }
    runtime = json.dumps(sanitize_for_log(value))
    recorded = json.dumps(redact(value))
    for secret in value.values():
        assert secret not in runtime
        assert secret not in recorded

    plain = sanitize_for_log(
        "person@example.test +38700000000 4147091234567890 BA-1234567890ABCDEF"
    )
    for secret in (
        "person@example.test",
        "+38700000000",
        "4147091234567890",
        "BA-1234567890ABCDEF",
    ):
        assert secret not in plain


def test_traffic_recorder_never_persists_raw_bodies_or_token_urls(
    tmp_path,
    monkeypatch,
) -> None:
    secrets = [
        "BA-1234567890ABCDEF",
        "EC-1234567890ABCDEF",
        "+66000000000",
        "person@example.test",
        "4147091234567890",
        "ACCESS-SECRET-TOKEN",
        "session=secret-cookie",
        "sa_nonce_SECRET",
    ]
    monkeypatch.setenv("PAYPAL_TRAFFIC_RECORD_RAW", "1")
    monkeypatch.setenv("PAYPAL_TRAFFIC_RECORD_RESPONSES", "1")
    recorder = TrafficRecorder(tmp_path / "capture")
    request_id = recorder.record_request(
        "POST",
        (
            "https://www.paypal.com/graphql?BuyerFundingContextQuery"
            "&token=EC-1234567890ABCDEF"
        ),
        {
            "json": {
                "ba_token": "BA-1234567890ABCDEF",
                "phone": "+66000000000",
                "email": "person@example.test",
                "cardNumber": "4147091234567890",
                "accessToken": "ACCESS-SECRET-TOKEN",
            }
        },
        headers={"Cookie": "session=secret-cookie"},
    )
    response = httpx.Response(
        200,
        json={"returnURL": "https://merchant.test/return/sa_nonce_SECRET"},
    )
    recorder.record_response(
        request_id,
        "POST",
        "https://www.paypal.com/graphql?token=EC-1234567890ABCDEF",
        response,
        error="person@example.test +66000000000 BA-1234567890ABCDEF",
    )
    recorder.close()

    assert recorder.raw_bodies is False
    assert recorder.response_bodies is False
    persisted = b"\n".join(
        path.read_bytes()
        for path in recorder.root.rglob("*")
        if path.is_file()
    ).decode("utf-8", errors="ignore")
    for secret in secrets:
        assert secret not in persisted


def test_headless_raw_debug_cannot_be_enabled(monkeypatch) -> None:
    monkeypatch.setenv("PAYPAL_HEADLESS_DEBUG", "1")
    monkeypatch.setenv("PAYPAL_HEADLESS_DEBUG_RAW", "1")
    assert headless_optimized_raw_debug_enabled() is False


def test_headless_metadata_debug_redacts_context_identifiers() -> None:
    event = _redact_debug_event(
        {
            "requestId": "REQUEST-SECRET",
            "authId": "AUTH-SECRET",
            "challengeId": "CHALLENGE-SECRET",
            "phone": "+66000000000",
            "email": "person@example.test",
        }
    )
    serialized = json.dumps(event)
    for secret in (
        "REQUEST-SECRET",
        "AUTH-SECRET",
        "CHALLENGE-SECRET",
        "+66000000000",
        "person@example.test",
    ):
        assert secret not in serialized
