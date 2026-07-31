import json
from pathlib import Path

import pytest
import httpx

from paypal.signup_lab import (
    BrowserSignupContext,
    CdpCapture,
    RoxySignupLab,
    SignupLabInputs,
    classify_signup_document,
    classify_signup_ui,
)
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


def test_signup_lab_inputs_route_bosnia_phone_and_proxy(tmp_path) -> None:
    source = tmp_path / "inputs-ba.json"
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["BA-12345678ABCDEF"],
                "phone": "+387644518746",
                "proxies": ["proxy.test:3010:ba-user:ba-password"],
            }
        ),
        encoding="utf-8",
    )

    inputs = SignupLabInputs.load(source)
    lab = RoxySignupLab(
        mode="reference",
        ba_token=inputs.selection()[0],
        phone=inputs.phone,
        proxy_line=inputs.selection()[1],
        capture_root=tmp_path / "capture",
    )

    assert lab.country_profile.country == "BA"
    assert lab.country_profile.language == "en-BA"
    assert lab.country_profile.timezone == "Europe/Sarajevo"
    assert lab.proxy_entry.username == "ba-user"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://www.paypal.com/checkoutweb/signup?token=EC-X", "legacy_checkoutweb"),
        ("https://www.paypal.com/pay/checkout/signup/contact", "contact_signup"),
        ("https://www.paypal.com/pay", "unknown"),
    ],
)
def test_signup_ui_generation(url: str, expected: str) -> None:
    assert classify_signup_ui(url) == expected


def test_contact_signup_stops_before_phone_submission() -> None:
    context = BrowserSignupContext()

    with pytest.raises(RuntimeError, match="ROXY_CONTACT_SIGNUP_STOPPED"):
        RoxySignupLab._stop_before_contact_submission(context)

    assert context.ui_generation == "contact_signup"
    assert context.stages[-1]["reason"] == "phone_submission_out_of_scope"


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


def test_cdp_capture_preserves_event_kind_and_transport_summary(tmp_path) -> None:
    capture = CdpCapture(None, tmp_path / "browser", pause_signup=False)
    capture._request({
        "requestId": "1",
        "type": "Document",
        "request": {"method": "GET", "url": "https://www.paypal.com/pay?token=secret"},
    })
    capture._response({
        "requestId": "1",
        "type": "Document",
        "response": {
            "url": "https://www.paypal.com/pay?token=secret",
            "status": 200,
            "protocol": "http/1.1",
            "mimeType": "text/html",
        },
    })

    rows = [json.loads(line) for line in capture.events_path.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["event_kind"] == "requestWillBeSent"
    assert rows[0]["resource_type"] == "Document"
    assert rows[1]["event_kind"] == "responseReceived"
    assert capture.transport_summary() == {
        "request_events": 1,
        "response_events": 1,
        "request_response_delta": 0,
        "loading_failed_events": 0,
        "https_protocol_counts": {"http/1.1": 1},
        "main_documents": [{
            "path": "/pay",
            "status": 200,
            "protocol": "http/1.1",
            "mime_type": "text/html",
        }],
    }


def test_browser_context_tracks_create_and_open_transport_args() -> None:
    context = BrowserSignupContext(
        browser_create_args=["--disable-http2"],
        browser_open_args=["--disable-http2"],
        http2_disabled_requested=True,
    )

    assert context.browser_create_args == context.browser_open_args
    assert context.http2_disabled_requested is True


def test_compare_supports_new_and_overwritten_legacy_cdp_events(tmp_path) -> None:
    protocol = tmp_path / "protocol" / "network"
    browser = tmp_path / "browser" / "network"
    protocol.mkdir(parents=True)
    browser.mkdir(parents=True)
    (protocol / "events.jsonl").write_text("", encoding="utf-8")
    events = [
        {
            "event_kind": "requestWillBeSent",
            "resource_type": "Document",
            "requestId": "new",
            "request": {"method": "GET", "url": "https://www.paypal.com/pay"},
        },
        {
            "event_kind": "responseReceived",
            "resource_type": "Document",
            "requestId": "new",
            "response": {"url": "https://www.paypal.com/pay", "status": 200, "protocol": "http/1.1"},
        },
        {
            "type": "Document",
            "requestId": "legacy",
            "request": {"method": "GET", "url": "https://www.paypal.com/checkoutweb/signup"},
        },
        {
            "type": "Document",
            "requestId": "legacy",
            "response": {"url": "https://www.paypal.com/checkoutweb/signup", "status": 403, "protocol": "h2"},
        },
    ]
    (browser / "events.jsonl").write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    report = compare(tmp_path / "protocol", tmp_path / "browser")

    assert report["browser_requests"] == 2
    assert report["browser_transport"]["https_protocol_counts"] == {"h2": 1, "http/1.1": 1}
    assert [doc["path"] for doc in report["browser_transport"]["main_documents"]] == [
        "/pay",
        "/checkoutweb/signup",
    ]


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
    assert "roxy_profile.json" in (root / "paypal/signup_lab.py").read_text(encoding="utf-8")


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


def test_passive_challenge_signals_are_observed_but_not_terminal() -> None:
    lab = object.__new__(RoxySignupLab)
    page = type("Page", (), {
        "url": "https://www.paypal.com/pay",
        "context": type("Context", (), {"cookies": lambda self: [{"name": "tsrce", "value": "authchallengenodeweb"}]})(),
    })()
    capture = type("Capture", (), {"challenge_urls": ["https://www.paypal.com/auth/createchallenge/x/hcaptchapassive.js"]})()

    terminal, observed = lab._challenge_evidence(page, capture, "ordinary pay page")

    assert terminal == []
    assert observed == ["tsrce_authchallenge", "passive_challenge_network"]


def test_pay_stage_uses_exact_application_email_form() -> None:
    source = Path(__file__).resolve().parents[1].joinpath("paypal/signup_lab.py").read_text(encoding="utf-8")
    pay_block = source.split('elif stage == "pay"', 1)[1].split('elif stage == "contact"', 1)[0]

    assert 'form[data-testid=\"emailForm\"]' in pay_block
    assert 'button[data-testid=\"continueButton\"]' in pay_block
    assert "pay_form_submitted = True" in pay_block
    assert "#loginButton" not in pay_block
    assert "pay_create_account_view_selected" in pay_block
