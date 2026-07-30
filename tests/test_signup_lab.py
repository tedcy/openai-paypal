import json
from pathlib import Path

import pytest
import httpx

from paypal.signup_lab import RoxySignupLab, SignupLabInputs, classify_signup_document
from paypal.traffic_recorder import TrafficRecorder
from tools.compare_paypal_traffic import compare


def test_signup_lab_inputs_select_without_network(tmp_path) -> None:
    source = tmp_path / "inputs.json"
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["https://www.paypal.com/agreements/approve?ba_token=BA-12345678ABCDEF"],
                "phone": "+17408803459",
                "proxies": ["proxy.test:3010:user:password"],
            }
        ),
        encoding="utf-8",
    )

    inputs = SignupLabInputs.load(source)

    assert inputs.selection() == ("BA-12345678ABCDEF", "proxy.test:3010:user:password")


def test_signup_lab_inputs_accept_utf8_bom(tmp_path) -> None:
    source = tmp_path / "inputs.json"
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["BA-12345678ABCDEF"],
                "phone": "+17408803459",
                "proxies": ["proxy.test:3010:user:password"],
            }
        ),
        encoding="utf-8-sig",
    )

    assert SignupLabInputs.load(source).selection()[0] == "BA-12345678ABCDEF"


def test_signup_document_requires_healthy_signup_html() -> None:
    valid = classify_signup_document(
        200,
        "text/html; charset=utf-8",
        "<html><script>window.__INITIAL_DATA__={}</script><div>checkoutweb signup</div></html>",
        "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
    )
    challenged = classify_signup_document(
        403,
        "text/html",
        "<html>DataDome Security Challenge</html>",
        "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
    )

    assert valid["valid"] is True
    assert challenged["valid"] is False
    assert set(challenged["challenge_markers"]) >= {"datadome", "security challenge"}


def test_signup_lab_rejects_missing_pool(tmp_path) -> None:
    source = tmp_path / "inputs.json"
    source.write_text(
        json.dumps({"ba_tokens": ["BA-12345678ABCDEF"], "phone": "+17408803459", "proxies": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="proxy"):
        SignupLabInputs.load(source)


def test_lab_raw_recorder_is_explicit_and_preserves_request(tmp_path) -> None:
    recorder = TrafficRecorder(tmp_path / "protocol", lab_raw=True)
    request_id = recorder.record_request(
        "GET",
        "https://www.paypal.com/checkoutweb/signup?token=EC-RAWVALUE123",
        headers={"Cookie": "session=raw-cookie"},
    )
    recorder.record_response(
        request_id,
        "GET",
        "https://www.paypal.com/checkoutweb/signup?token=EC-RAWVALUE123",
        httpx.Response(200, text="checkoutweb signup"),
    )
    recorder.close()

    persisted = (recorder.events_file).read_text(encoding="utf-8")
    assert "EC-RAWVALUE123" in persisted
    assert "session=raw-cookie" in persisted


def test_compare_aligns_by_stage_method_and_path(tmp_path) -> None:
    protocol = tmp_path / "protocol" / "network"
    browser = tmp_path / "browser" / "network"
    protocol.mkdir(parents=True)
    browser.mkdir(parents=True)
    (protocol / "events.jsonl").write_text(
        json.dumps({"type": "request", "method": "GET", "url": "https://www.paypal.com/checkoutweb/signup?token=EC-X", "headers": {"Cookie": "a=1"}}) + "\n",
        encoding="utf-8",
    )
    (browser / "events.jsonl").write_text(
        json.dumps({"type": "requestWillBeSent", "requestId": "1", "request": {"method": "GET", "url": "https://www.paypal.com/checkoutweb/signup?token=EC-X", "headers": {"Cookie": "a=1"}}}) + "\n",
        encoding="utf-8",
    )

    report = compare(tmp_path / "protocol", tmp_path / "browser")

    assert report["protocol_requests"] == 1
    assert report["browser_requests"] == 1
    assert report["pairs"][0]["key"].startswith("signup:GET:")


def test_signup_lab_contains_no_network_or_cdp_discovery() -> None:
    root = Path(__file__).resolve().parents[1]
    sources = "\n".join(
        (root / relative).read_text(encoding="utf-8")
        for relative in ("paypal/signup_lab.py", "tools/roxy_cdp_capture.mjs")
    ).lower()
    forbidden = (
        "getaddrinfo",
        "nslookup",
        "netstat",
        "ss', ['-ltnp",
        "resolve-dnsname",
        "api.ipify",
        "ifconfig.me",
        "discover ports",
    )
    for marker in forbidden:
        assert marker not in sources


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://www.paypal.com/agreements/approve?ba_token=BA-X", "approval"),
        ("https://www.paypal.com/pay?token=BA-X", "pay"),
        ("https://www.paypal.com/pay/checkout/signup/contact?token=BA-X", "contact"),
        ("https://www.paypal.com/checkoutweb/signup?token=EC-X", "checkoutweb_signup"),
    ],
)
def test_roxy_signup_lab_classifies_navigation_stage(url: str, expected: str) -> None:
    assert RoxySignupLab._page_stage(url) == expected
