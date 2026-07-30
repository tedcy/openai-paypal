import json
from pathlib import Path

from paypal.flow import PayPalFlow
from paypal.funding import FUNDING_CONTINUE, FUNDING_RESTRICTED, classify_buyer_funding_context


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "graphql_flow_cases.json"


def _fixtures():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_sanitized_signup_fixtures_distinguish_retry_from_commit() -> None:
    fixtures = _fixtures()
    validate_error = fixtures["validate_fi_without_token"]
    recoverable = [
        fixtures["r_error_with_token"],
        fixtures["issuer_decline_with_token"],
    ]

    assert PayPalFlow._find_access_token(validate_error) == ""
    assert PayPalFlow._is_card_related_signup_error(validate_error["errors"])
    for response in recoverable:
        assert PayPalFlow._is_card_related_signup_error(response["errors"])
        assert PayPalFlow._find_access_token(response) == "<redacted-access-token>"


def test_sanitized_funding_fixtures_cover_continue_and_restricted() -> None:
    fixtures = _fixtures()
    non_payable = classify_buyer_funding_context(fixtures["funding_non_payable"])
    restricted = classify_buyer_funding_context(fixtures["funding_restricted"])

    assert non_payable.status == FUNDING_CONTINUE
    assert non_payable.state == "NON_PAYABLE"
    assert restricted.status == FUNDING_RESTRICTED


def test_sanitized_authorize_fixtures_cover_success_and_buyer_not_set() -> None:
    fixtures = _fixtures()
    success = fixtures["authorize_success"]
    retry = fixtures["authorize_buyer_not_set"]

    assert not PayPalFlow._has_buyer_not_set(success)
    assert PayPalFlow._has_buyer_not_set(retry)
    authorize = success[0]["data"]["billing"]["authorize"]
    assert authorize["paymentAction"] == "SALE"
    assert authorize["buyer"]["userId"] == "PAYER_FIXTURE"


def test_graphql_fixture_file_contains_no_runtime_secrets() -> None:
    serialized = FIXTURE_PATH.read_text(encoding="utf-8")
    for forbidden in ("BA-0UT", "EC-9EA", "+55", "+66", "+387", "@gmail.com"):
        assert forbidden not in serialized
