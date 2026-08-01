import json
from types import SimpleNamespace
import urllib.parse

import pytest

from paypal.country import profile_for_country
from paypal.flow import PayPalFlow
from paypal.models import SessionState, generate_address, generate_card, generate_user
from paypal.session import CurlHttpVersion, PayPalSession, build_common_headers, build_high_entropy_hints


def _bare_flow(country: str) -> PayPalFlow:
    phones = {
        "BR": "+5500000000000",
        "TH": "+66000000000",
        "BA": "+38700000000",
        "US": "+12025550123",
    }
    profile = profile_for_country(country)
    flow = PayPalFlow.__new__(PayPalFlow)
    flow.country_profile = profile
    flow.user = generate_user(phones[country], profile)
    flow.card = generate_card()
    flow.address = generate_address(profile)
    flow.state = SessionState(ba_token="BA-12345678ABCDEFG")
    flow.state.content_identifier = f"{country}:{profile.graphql_language}:compliance.signupTerms"
    flow._billing_address_autocomplete_succeeded = country == "BR"
    flow._content_metadata_is_unresolved = lambda: False
    flow._resolved_content_identifier = lambda: flow.state.content_identifier
    return flow


@pytest.mark.parametrize("country", ["BR", "TH", "BA", "US"])
def test_signup_variables_are_country_specific(country: str) -> None:
    flow = _bare_flow(country)
    variables = flow._build_signup_variables("EC-12345678ABCDEFG")
    assert variables["country"] == country
    assert variables["phone"]["countryCode"] == flow.country_profile.dial_prefix.lstrip("+")
    if country == "BR":
        assert variables["identityDocument"]["type"] == "CPF"
        assert variables["billingAddress"]["state"]
        assert variables["billingAddress"]["accountQuality"]["autoCompleteType"] == "ANS"
    else:
        assert "identityDocument" not in variables
        assert variables["billingAddress"]["accountQuality"]["autoCompleteType"] == "MANUAL"
    if country == "BA":
        assert "state" not in variables["billingAddress"]
    if country == "US":
        assert variables["phone"]["countryCode"] == "1"
        assert variables["billingAddress"]["state"] in {"IL", "WI", "MN", "MO"}
        assert variables["billingAddress"]["line1"] == (
            f"{flow.address.house_number} {flow.address.street}"
        )


def test_phone_update_rejects_cross_country_change() -> None:
    flow = _bare_flow("TH")
    flow._on_phone_updated = lambda: None
    flow._update_user_phone("+66000000001")
    assert flow.user.phone == "+66000000001"
    with pytest.raises(ValueError, match="cannot change"):
        flow._update_user_phone("+38700000000")


def test_modxo_router_state_is_derived_from_current_flight_html() -> None:
    flow = _bare_flow("BA")
    html = (
        '<script>self.__next_f.push([1,"'
        '\\"children\\":[\\"(identity)\\",{'
        '\\"children\\":[\\"__PAGE__\\",{}],'
        '\\"authFlow\\":[\\"(__SLOT__)\\",{}],'
        '\\"emailUl\\":[\\"(__SLOT__)\\",{}],'
        '\\"onboarding\\":[\\"(__SLOT__)\\",{}],'
        '\\"pushLogin\\":[\\"(__SLOT__)\\",{}],'
        '\\"pushLoginStatus\\":[\\"(__SLOT__)\\",{}],'
        '\\"tokenizedLogin\\":[\\"(__SLOT__)\\",{}]'
        ']},\\"$undefined\\",\\"$undefined\\",16]'
        '"])</script>'
    )

    assert flow._apply_modxo_router_state(html) is True
    assert flow.state.modxo_router_slot_names == [
        "authFlow",
        "emailUl",
        "onboarding",
        "pushLogin",
        "pushLoginStatus",
        "tokenizedLogin",
    ]

    tree = json.loads(urllib.parse.unquote(flow._modxo_router_state_tree_header()))
    identity_routes = tree[1]["children"][1]
    assert list(identity_routes) == [
        "children",
        "authFlow",
        "emailUl",
        "onboarding",
        "pushLogin",
        "pushLoginStatus",
        "tokenizedLogin",
    ]
    assert identity_routes["pushLoginStatus"] == [
        "(__SLOT__)",
        {"children": ["__PAGE__", {}, None, None, 0]},
        None,
        None,
        0,
    ]


def test_modxo_router_state_rejects_incomplete_flight_fragment() -> None:
    flow = _bare_flow("BA")

    assert flow._apply_modxo_router_state(
        '\\"children\\":[\\"(identity)\\",{'
        '\\"authFlow\\":[\\"(__SLOT__)\\",{}]}'
    ) is False
    assert flow.state.modxo_router_slot_names == []


def test_cold_protocol_stops_on_soft_200_approval_before_phase2() -> None:
    flow = _bare_flow("BA")
    phase2_calls = []
    flow._log_flow_attempt_start = lambda _attempt: None

    def soft_approval() -> None:
        flow._last_approval_status = 200
        flow._last_modxo_html = "<html>datadome soft challenge</html>"

    flow._phase0_initial_load = soft_approval
    flow._phase2_create_account = lambda: phase2_calls.append(True)
    flow._safe_error_text = str
    flow.close = lambda: None

    result = flow.run_until_signup()

    assert result["status"] == "failed"
    assert "PROTOCOL_APPROVAL_APPLICATION_MISSING" in result["error"]
    assert result["approval_status"] == 200
    assert result["approval_application_shape"] is False
    assert result["approval_next_flight"] is False
    assert result["approval_has_ssrt"] is False
    assert result["approval_has_ctx_id"] is False
    assert result["approval_router_slot_count"] == 0
    assert phase2_calls == []


def test_cold_protocol_approval_shape_requires_current_flight_context() -> None:
    flow = _bare_flow("BA")
    flow._last_approval_status = 200
    flow._last_modxo_html = "<script>self.__next_f.push([])</script>"
    flow.state.ssrt = "1785561075940"
    flow.state.ctx_id = "ctx-current"
    flow.state.modxo_router_slot_names = [
        "authFlow",
        "emailUl",
        "onboarding",
        "tokenizedLogin",
    ]

    assert flow._protocol_approval_application_ready() is True
    assert flow._protocol_approval_diagnostic() == {
        "approval_status": 200,
        "approval_body_bytes": len(flow._last_modxo_html.encode("utf-8")),
        "approval_application_shape": True,
        "approval_next_flight": True,
        "approval_has_ssrt": True,
        "approval_has_ctx_id": True,
        "approval_router_slot_count": 4,
    }


def test_full_protocol_rejects_generic_error_before_phase3() -> None:
    flow = _bare_flow("US")
    flow.max_flow_attempts = 1
    flow.require_valid_signup_document = True
    flow._log_flow_attempt_start = lambda _attempt: None
    flow.close = lambda: None
    calls: list[str] = []

    def phase0() -> None:
        calls.append("phase0")

    def phase2() -> None:
        calls.append("phase2")
        flow._last_signup_status = 200
        flow._last_signup_url = "https://www.paypal.com/checkoutweb/genericError?code=TEST"
        flow._last_signup_content_type = "text/html; charset=utf-8"
        flow._last_signup_html = "<html><div>genericError</div></html>"

    flow._phase0_initial_load = phase0
    flow._phase2_create_account = phase2
    flow._phase3_signup_and_2fa = lambda: calls.append("phase3")
    flow._phase4_authorize = lambda: calls.append("phase4")

    with pytest.raises(
        RuntimeError,
        match=r"PROTOCOL_SIGNUP_DOCUMENT_INVALID:.*unexpected_path",
    ):
        flow.run()

    assert calls == ["phase0", "phase2"]


def test_signup_response_diagnostic_resolves_redirect_location() -> None:
    flow = _bare_flow("US")
    flow._remember_signup_response(
        SimpleNamespace(
            status_code=302,
            text="",
            url="https://www.paypal.com/checkoutweb/signup?token=EC-SECRET",
            headers={"Location": "/checkoutweb/genericError?code=TEST"},
        )
    )

    assert flow._last_signup_status == 302
    assert flow._last_signup_url == "https://www.paypal.com/checkoutweb/genericError?code=TEST"
    assert flow._last_signup_content_type == ""


class _OtpGraphqlSession:
    def __init__(self, result: dict[str, object], status: int = 200) -> None:
        self.result = result
        self.status = status
        self.last_graphql_response_meta: dict[str, object] = {}

    def graphql(self, operation_name, *_args, **_kwargs):
        self.last_graphql_response_meta = {
            "operation_name": operation_name,
            "http_status": self.status,
            "json_parsed": True,
        }
        return self.result


def test_otp_http_200_rejected_state_is_not_business_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("paypal.flow.send_weasley_log", lambda *_args, **_kwargs: None)
    flow = _bare_flow("US")
    flow.session = _OtpGraphqlSession(
        {
            "data": {
                "confirmRiskBasedTwoFactorPhoneConfirmation": {
                    "state": "REJECTED",
                }
            }
        }
    )
    outcomes: list[dict[str, object]] = []
    flow._on_otp_business_result = lambda _operation, outcome: outcomes.append(outcome)

    confirmed = flow._confirm_2fa_phone_confirmation(
        "EC-12345678ABCDEFG",
        "https://www.paypal.com/checkoutweb/signup",
        "AUTH-ID",
        "CHALLENGE-ID",
        "123456",
    )

    assert confirmed is False
    assert outcomes == [
        {
            "operation": "ConfirmRiskBasedTwoFactorPhoneConfirmationMutation",
            "http_status": 200,
            "business_success": False,
            "state": "REJECTED",
            "error_count": 0,
            "errors": [],
        }
    ]


def test_otp_confirm_requires_confirmed_state_without_graphql_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("paypal.flow.send_weasley_log", lambda *_args, **_kwargs: None)
    flow = _bare_flow("US")
    flow.session = _OtpGraphqlSession(
        {
            "data": {
                "confirmRiskBasedTwoFactorPhoneConfirmation": {
                    "state": "CONFIRMED",
                }
            },
            "errors": [{"message": "confirmation warning", "extensions": {"code": "OTP_ERROR"}}],
        }
    )
    outcomes: list[dict[str, object]] = []
    flow._on_otp_business_result = lambda _operation, outcome: outcomes.append(outcome)

    assert flow._confirm_2fa_phone_confirmation(
        "EC-12345678ABCDEFG",
        "https://www.paypal.com/checkoutweb/signup",
        "AUTH-ID",
        "CHALLENGE-ID",
        "123456",
    ) is False
    assert outcomes[0]["http_status"] == 200
    assert outcomes[0]["business_success"] is False
    assert outcomes[0]["state"] == "CONFIRMED"
    assert outcomes[0]["error_count"] == 1


def test_otp_initiate_http_200_requires_business_auth_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("paypal.flow.send_weasley_log", lambda *_args, **_kwargs: None)
    flow = _bare_flow("US")
    flow.session = _OtpGraphqlSession(
        {
            "data": {
                "initiateRiskBasedTwoFactorPhoneConfirmation": {
                    "state": "FAILED",
                }
            }
        }
    )
    outcomes: list[dict[str, object]] = []
    flow._on_otp_business_result = lambda _operation, outcome: outcomes.append(outcome)

    with pytest.raises(RuntimeError, match="OTP_INITIATION_BUSINESS_FAILED"):
        flow._initiate_2fa_phone_confirmation(
            "EC-12345678ABCDEFG",
            "https://www.paypal.com/checkoutweb/signup",
        )

    assert outcomes[0]["http_status"] == 200
    assert outcomes[0]["business_success"] is False
    assert outcomes[0]["state"] == "FAILED"


def test_shared_paypal_session_supports_curl_chrome_http1() -> None:
    if CurlHttpVersion is None:
        pytest.skip("curl_cffi is not installed")
    session = PayPalSession(
        SessionState(ba_token="BA-12345678ABCDEFG"),
        transport="curl-chrome-http1",
    )
    try:
        prepared = session._prepare_curl_kwargs({})
        assert session._use_curl is True
        assert session._curl_http1 is True
        assert prepared["http_version"] == CurlHttpVersion.V1_1
    finally:
        session.close()


def test_ios_crios_profile_omits_user_agent_client_hints() -> None:
    state = SessionState(ba_token="BA-12345678ABCDEFG")
    state.browser_profile = {
        "user_agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "CriOS/136.0.7103.60 Mobile/15E148 Safari/537.36"
        ),
        "platform": "iPhone",
        "language": "en-BA",
        "ua_client_hints_enabled": False,
        "mobile": True,
    }

    headers = build_common_headers(state)

    assert headers["User-Agent"].find("CriOS/136.") > 0
    assert headers["Accept-Language"] == "en-BA,en;q=0.9,en-US;q=0.8"
    assert not any(name.lower().startswith("sec-ch-") for name in headers)
    assert build_high_entropy_hints(state) == {}


def test_shared_paypal_session_accepts_explicit_chrome136_impersonation() -> None:
    if CurlHttpVersion is None:
        pytest.skip("curl_cffi is not installed")
    state = SessionState(ba_token="BA-12345678ABCDEFG")
    state.browser_profile = {
        "user_agent": "Mozilla/5.0 CriOS/136.0.7103.60 Mobile/15E148",
        "platform": "iPhone",
        "language": "en-BA",
        "ua_client_hints_enabled": False,
    }
    session = PayPalSession(
        state,
        transport="curl-chrome-http1",
        curl_impersonate="chrome136",
    )
    try:
        assert session._curl_impersonate == "chrome136"
        assert session._curl_default_headers is False
        assert not any(
            str(name).lower().startswith("sec-ch-")
            for name in session.client.headers
        )
    finally:
        session.close()


def test_partial_signup_token_commits_and_prevents_second_signup() -> None:
    flow = _bare_flow("BR")
    flow.max_card_attempts = 5
    flow.card_retry_delay_seconds = 0
    flow.card_retry_jitter_seconds = 0
    flow._signup_billing_address_prepared = False
    flow._used_partial_signup_token = False
    calls = {"send": 0}
    errors = [{"message": "ISSUER_DECLINE", "checkpoints": ["addCard"]}]

    def send(_token: str, _url: str):
        calls["send"] += 1
        return {"errors": errors}

    flow._send_signup_attempt = send
    flow._consume_signup_result = lambda _result, _url: (False, errors)
    flow._signup_access_token_candidate = lambda _result: "ACCESS-TOKEN"
    flow._wait_and_rotate_card = lambda _reason: pytest.fail("must not rotate after token")
    flow._signup_with_card_retry("EC-12345678ABCDEFG", "https://ctf.invalid/signup")
    assert calls["send"] == 1
    assert flow.state.signup_committed is True
    assert flow.state.euat_token == "ACCESS-TOKEN"

    flow._signup_with_card_retry("EC-12345678ABCDEFG", "https://ctf.invalid/signup")
    assert calls["send"] == 1


def test_card_error_without_token_rotates_then_succeeds() -> None:
    flow = _bare_flow("BR")
    flow.max_card_attempts = 2
    flow.card_retry_delay_seconds = 0
    flow.card_retry_jitter_seconds = 0
    flow._signup_billing_address_prepared = False
    flow._used_partial_signup_token = False
    calls = {"send": 0, "rotate": 0}
    errors = [
        {
            "message": "CREATE_CARD_ACCOUNT_CANDIDATE_VALIDATION_ERROR",
            "checkpoints": ["validate.fi"],
        }
    ]

    def send(_token: str, _url: str):
        calls["send"] += 1
        return {"attempt": calls["send"]}

    def consume(result, _url):
        return (True, []) if result["attempt"] == 2 else (False, errors)

    flow._send_signup_attempt = send
    flow._consume_signup_result = consume
    flow._signup_access_token_candidate = lambda _result: ""
    flow._wait_and_rotate_card = lambda _reason: calls.__setitem__("rotate", calls["rotate"] + 1)
    flow._signup_with_card_retry("EC-12345678ABCDEFG", "https://ctf.invalid/signup")
    assert calls == {"send": 2, "rotate": 1}
    assert flow.state.signup_committed is True


def test_exhausted_card_retry_does_not_restart_the_full_flow() -> None:
    flow = _bare_flow("BR")
    flow.state.signup_committed = False
    assert flow._should_retry_full_flow_exception(
        RuntimeError("Signup failed: card was rejected after 5 attempts")
    ) is False


class _AuthorizeSession:
    def __init__(self) -> None:
        self.calls = 0

    def graphql(self, *_args, **_kwargs):
        self.calls += 1
        return [{"errors": [{"message": "BUYER_NOT_SET"}], "data": {"billing": None}}]


def test_buyer_not_set_refreshes_once_without_outer_retry() -> None:
    flow = _bare_flow("BR")
    flow.ba_token = "BA-12345678ABCDEFG"
    flow.state.ec_token = "EC-12345678ABCDEFG"
    flow.state.signup_url = "https://ctf.invalid/signup"
    flow.state.signup_committed = True
    flow.state.euat_token = "ACCESS-TOKEN"
    flow.state.ssrt = "ssrt"
    flow.state.signup_fallback_reason = ""
    flow.max_authorize_attempts = 2
    flow._used_partial_signup_token = True
    flow.session = _AuthorizeSession()
    counters = {"review": 0, "funding": 0}
    flow._load_hagrid_review_context = lambda *_args: counters.__setitem__("review", counters["review"] + 1)
    flow._refresh_buyer_funding_context = lambda: counters.__setitem__("funding", counters["funding"] + 1)
    flow._send_tealeaf_data = lambda *_args, **_kwargs: None
    flow._send_datadog_rum_view = lambda *_args, **_kwargs: None
    flow._send_datadog_rum_action = lambda *_args, **_kwargs: None
    flow._authorize_metadata_candidates = lambda: ["metadata"]

    result = flow._phase4_authorize()
    assert result["reason"] == "BUYER_NOT_SET"
    assert result["retryable"] is False
    assert flow.session.calls == 2
    assert counters == {"review": 2, "funding": 1}
    assert flow._should_retry_full_flow(result) is False


class _SuccessfulAuthorizeSession:
    def __init__(self) -> None:
        self.calls = 0

    def graphql(self, *_args, **_kwargs):
        self.calls += 1
        return [
            {
                "data": {
                    "billing": {
                        "authorize": {
                            "billingAgreementToken": "BA-12345678ABCDEFG",
                            "paymentAction": "SALE",
                            "returnURL": {
                                "href": (
                                    "https://pm-redirects.stripe.com/return/"
                                    "acct_SECRET/sa_nonce_SECRET?status=success&token=EC-SECRET12345678"
                                )
                            },
                            "buyer": {"userId": "PAYER123456"},
                        }
                    }
                }
            }
        ]


def test_authorize_success_returns_only_sanitized_merchant_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _bare_flow("TH")
    flow.ba_token = "BA-12345678ABCDEFG"
    flow.state.ec_token = "EC-12345678ABCDEFG"
    flow.state.signup_url = "https://ctf.invalid/signup"
    flow.state.signup_committed = True
    flow.state.euat_token = "ACCESS-TOKEN"
    flow.state.ssrt = "ssrt"
    flow.state.signup_fallback_reason = ""
    flow.max_authorize_attempts = 2
    flow._used_partial_signup_token = False
    flow.session = _SuccessfulAuthorizeSession()
    flow._load_hagrid_review_context = lambda *_args: True
    flow._send_tealeaf_data = lambda *_args, **_kwargs: None
    flow._send_datadog_rum_view = lambda *_args, **_kwargs: None
    flow._send_datadog_rum_action = lambda *_args, **_kwargs: None
    flow._authorize_metadata_candidates = lambda: ["metadata"]
    monkeypatch.setattr("paypal.flow.send_analytics_ts", lambda *_args, **_kwargs: None)

    result = flow._phase4_authorize()
    assert result["status"] == "success"
    assert result["authorization_status"] == "AUTHORIZED"
    assert result["billing_agreement_token"] == "BA-12345678ABCDEFG"
    assert result["buyer_id"] == "PAYER123456"
    assert result["payment_action"] == "SALE"
    assert "acct_SECRET" not in result["return_url"]
    assert "sa_nonce_SECRET" not in result["return_url"]
    assert "EC-SECRET12345678" not in result["return_url"]
    assert "<redacted>" in result["return_url"]
    assert "final_redirect_url" not in result
    assert flow.session.calls == 1


def test_simulated_complete_flow_runs_all_protocol_phases_without_network() -> None:
    flow = _bare_flow("BA")
    flow.max_flow_attempts = 1
    events: list[str] = []
    flow._log_flow_attempt_start = lambda _attempt: events.append("start")
    flow._phase0_initial_load = lambda: events.append("phase0")
    flow._phase2_create_account = lambda: events.append("phase2")

    def phase3() -> None:
        flow.state.signup_committed = True
        events.append("phase3")

    def phase4():
        assert flow.state.signup_committed is True
        events.append("phase4")
        return {"status": "success", "authorization_status": "AUTHORIZED"}

    flow._phase3_signup_and_2fa = phase3
    flow._phase4_authorize = phase4
    flow._with_risk_runtime_report = lambda result: result
    flow.close = lambda: events.append("close")

    result = flow.run()
    assert result["status"] == "success"
    assert events == ["start", "phase0", "phase2", "phase3", "phase4", "close"]
