"""Classification helpers for BuyerFundingContextQuery responses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator


FUNDING_CONTINUE = "CONTINUE"
FUNDING_RESTRICTED = "IDENTITY_ELEVATION_PAYER_RESTRICTED"
FUNDING_FAILED = "BUYER_FUNDING_CONTEXT_FAILED"


@dataclass(frozen=True, slots=True)
class FundingContextResult:
    status: str
    payer_id: str = ""
    state: str = ""
    reason: str = ""


def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _text_markers(value: Any) -> set[str]:
    markers: set[str] = set()
    for item in _walk(value):
        if isinstance(item, str):
            markers.add(item.upper())
    return markers


def _payer_id(value: Any) -> str:
    for item in _walk(value):
        if not isinstance(item, dict):
            continue
        for key in ("payer", "buyer"):
            payer = item.get(key)
            if isinstance(payer, dict):
                candidate = payer.get("id") or payer.get("userId") or payer.get("user_id")
                if isinstance(candidate, str) and candidate:
                    return candidate
        candidate = item.get("payerId") or item.get("buyerId")
        if isinstance(candidate, str) and candidate:
            return candidate
    return ""


def _state(value: Any) -> str:
    for item in _walk(value):
        if isinstance(item, dict):
            candidate = item.get("state")
            if isinstance(candidate, str) and candidate:
                return candidate.upper()
    return ""


def _checkout_session(value: Any) -> dict[str, Any] | None:
    for item in _walk(value):
        if isinstance(item, dict) and isinstance(item.get("checkoutSession"), dict):
            return item["checkoutSession"]
    return None


def classify_buyer_funding_context(value: Any) -> FundingContextResult:
    """Map a GraphQL response to the flow's three funding outcomes."""
    if not isinstance(value, (dict, list)):
        return FundingContextResult(FUNDING_FAILED, reason="response is not JSON object/list")

    markers = _text_markers(value)
    payer_id = _payer_id(value)
    state = _state(value)

    if "PAYER_ACCOUNT_RESTRICTED" in markers:
        return FundingContextResult(
            FUNDING_RESTRICTED,
            payer_id=payer_id,
            state=state,
            reason="PAYER_ACCOUNT_RESTRICTED",
        )

    if state == "NON_PAYABLE" or "NON_PAYABLE" in markers:
        if payer_id:
            return FundingContextResult(
                FUNDING_CONTINUE,
                payer_id=payer_id,
                state="NON_PAYABLE",
                reason="NON_PAYABLE_WITH_PAYER_CONTEXT",
            )
        return FundingContextResult(
            FUNDING_FAILED,
            state="NON_PAYABLE",
            reason="NON_PAYABLE response did not contain payer context",
        )

    items = value if isinstance(value, list) else [value]
    errors = [
        error
        for item in items
        if isinstance(item, dict)
        for error in (item.get("errors") or [])
    ]
    if errors:
        return FundingContextResult(
            FUNDING_FAILED,
            payer_id=payer_id,
            state=state,
            reason="GraphQL funding resolver returned unclassified errors",
        )

    checkout_session = _checkout_session(value)
    if checkout_session is not None:
        funding_options = checkout_session.get("fundingOptions")
        if not isinstance(funding_options, (dict, list)):
            return FundingContextResult(
                FUNDING_FAILED,
                payer_id=payer_id,
                state=state,
                reason="checkoutSession.fundingOptions is missing or has an invalid shape",
            )
        return FundingContextResult(
            FUNDING_CONTINUE,
            payer_id=payer_id,
            state=state or "PAYABLE",
            reason="funding context resolved",
        )

    return FundingContextResult(
        FUNDING_FAILED,
        payer_id=payer_id,
        state=state,
        reason="checkoutSession funding context is missing",
    )
