import httpx
import pytest

from paypal.funding import (
    FUNDING_CONTINUE,
    FUNDING_FAILED,
    FUNDING_RESTRICTED,
    classify_buyer_funding_context,
)
from paypal.models import SessionState
from paypal.session import PayPalSession


def test_non_payable_with_payer_context_can_continue() -> None:
    result = {
        "errors": [
            {
                "data": {
                    "payer": {"id": "TESTPAYER12345", "email": "masked@example.test"},
                    "state": "NON_PAYABLE",
                    "fundingOptions": {},
                }
            }
        ]
    }
    outcome = classify_buyer_funding_context(result)
    assert outcome.status == FUNDING_CONTINUE
    assert outcome.payer_id == "TESTPAYER12345"
    assert outcome.state == "NON_PAYABLE"


def test_payer_restricted_stops_flow() -> None:
    result = {
        "errors": [
            {
                "message": "PAYER_ACCOUNT_RESTRICTED",
                "checkpoints": ["createCheckoutSession"],
                "path": ["checkoutSession", "fundingOptions"],
            }
        ]
    }
    outcome = classify_buyer_funding_context(result)
    assert outcome.status == FUNDING_RESTRICTED
    assert outcome.reason == "PAYER_ACCOUNT_RESTRICTED"


def test_non_payable_without_payer_is_schema_failure() -> None:
    outcome = classify_buyer_funding_context({"errors": [{"data": {"state": "NON_PAYABLE"}}]})
    assert outcome.status == FUNDING_FAILED


def test_successful_checkout_session_can_continue() -> None:
    outcome = classify_buyer_funding_context(
        {"data": {"checkoutSession": {"buyer": {"userId": "PAYER123"}, "fundingOptions": {}}}}
    )
    assert outcome.status == FUNDING_CONTINUE
    assert outcome.payer_id == "PAYER123"


def test_unclassified_graphql_error_is_failure() -> None:
    outcome = classify_buyer_funding_context(
        {"errors": [{"message": "GRAPHQL_VALIDATION_FAILED"}], "data": None}
    )
    assert outcome.status == FUNDING_FAILED


def test_checkout_session_without_funding_shape_is_failure() -> None:
    outcome = classify_buyer_funding_context(
        {"data": {"checkoutSession": {"buyer": {"userId": "PAYER123"}}}}
    )
    assert outcome.status == FUNDING_FAILED
    assert "fundingOptions" in outcome.reason


def test_funding_graphql_can_require_http_success() -> None:
    session = PayPalSession.__new__(PayPalSession)
    session.state = SessionState(ba_token="BA-TESTTOKEN123456")
    session.post = lambda *_args, **_kwargs: httpx.Response(
        503,
        json={"errors": [{"message": "SERVICE_UNAVAILABLE"}]},
    )

    with pytest.raises(RuntimeError, match="HTTP 503"):
        session.graphql(
            "BuyerFundingContextQuery",
            "query BuyerFundingContextQuery { checkoutSession { fundingOptions } }",
            {"token": "EC-TESTTOKEN123456"},
            require_http_success=True,
        )
