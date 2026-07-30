from types import SimpleNamespace

import pytest

from paypal.country import profile_for_country
from paypal.flow import PayPalFlow
from paypal.models import SessionState, generate_address, generate_card, generate_user


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
