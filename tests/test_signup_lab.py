import inspect
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx

from paypal.signup_lab import (
    ApprovalCdpObserver,
    BrowserSignupContext,
    CdpCapture,
    RoxyApprovalControl,
    RoxySignupLab,
    SignupLabInputs,
    _approval_document_has_status,
    _configure_roxy_for_signup_lab,
    _hash,
    _safe_existing_profile_detail,
    audit_jsonl_capture,
    classify_approval_document,
    classify_signup_document,
    classify_signup_ui,
    clear_existing_profile_state,
    run_approval_control_from_file,
    run_signup_lab_from_file,
)
from paypal.proxy import ProxyEntry
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
                "phone": "+38761123456",
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


def test_manual_navigation_requires_explicit_existing_profile(tmp_path) -> None:
    with pytest.raises(ValueError, match="manual navigation requires"):
        RoxySignupLab(
            mode="reference",
            ba_token="BA-12345678ABCDEF",
            phone="+38761123456",
            proxy_line="proxy.test:3010:user:password",
            capture_root=tmp_path / "capture",
            manual_navigation=True,
        )


def test_signup_lab_reserves_a_new_non_quarantined_proxy_for_each_profile(tmp_path) -> None:
    source = tmp_path / "inputs.json"
    first = "proxy-a.test:3010:user:password-a"
    second = "proxy-b.test:3010:user:password-b"
    third = "proxy-c.test:3010:user:password-c"
    first_hash = _hash(ProxyEntry.parse(first).url)
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["BA-12345678ABCDEF"],
                "phone": "+38761123456",
                "proxies": [first, second, third],
                "failed_proxy_hashes": [first_hash],
                "next_proxy_index": 0,
            }
        ),
        encoding="utf-8",
    )

    _, _, selected_one, reservation_one = SignupLabInputs.reserve_for_profile(source)
    _, _, selected_two, reservation_two = SignupLabInputs.reserve_for_profile(source)

    assert selected_one == second
    assert reservation_one["selected_proxy_index"] == 1
    assert reservation_one["next_proxy_index"] == 2
    assert selected_two == third
    assert reservation_two["selected_proxy_index"] == 2
    assert json.loads(source.read_text(encoding="utf-8"))["next_proxy_index"] == 0


def test_signup_lab_quarantines_approval_403_proxy_without_logging_credentials(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "inputs.json"
    first = "proxy-a.test:3010:user:password-a"
    second = "proxy-b.test:3010:user:password-b"
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["BA-12345678ABCDEF"],
                "phone": "+38761123456",
                "proxies": [first, second],
                "next_proxy_index": 0,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        RoxySignupLab,
        "run",
        lambda self: {
            "status": "failed",
            "browser_transport": {
                "main_documents": [
                    {"path": "/agreements/approve", "status": 403, "protocol": "http/1.1"}
                ]
            },
        },
    )
    capture = tmp_path / "capture"

    result = run_signup_lab_from_file(
        mode="reference",
        input_file=source,
        capture_dir=capture,
    )

    first_hash = _hash(ProxyEntry.parse(first).url)
    state = json.loads(source.read_text(encoding="utf-8"))
    rotation_text = (capture / "proxy_rotation.json").read_text(encoding="utf-8")
    assert state["next_proxy_index"] == 1
    assert state["failed_proxy_hashes"] == [first_hash]
    assert result["proxy_rotation"]["approval_403_quarantined"] is True
    assert result["proxy_rotation"]["proxy_hash"] == first_hash
    assert "password-a" not in rotation_text
    assert "proxy-a.test" not in rotation_text


def test_cold_protocol_does_not_advance_proxy_cursor(tmp_path, monkeypatch) -> None:
    source = tmp_path / "inputs.json"
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["BA-12345678ABCDEF"],
                "phone": "+38761123456",
                "proxies": [
                    "proxy-a.test:3010:user:password-a",
                    "proxy-b.test:3010:user:password-b",
                ],
                "next_proxy_index": 1,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "paypal.signup_lab.run_cold_protocol_signup",
        lambda **kwargs: {"status": "failed"},
    )

    result = run_signup_lab_from_file(
        mode="cold-protocol",
        input_file=source,
        capture_dir=tmp_path / "capture",
    )

    assert json.loads(source.read_text(encoding="utf-8"))["next_proxy_index"] == 1
    assert result["proxy_rotation"]["cursor_advanced"] is False
    assert result["proxy_rotation"]["reason"] == "cold_protocol_creates_no_roxy_profile"


def test_existing_profile_control_does_not_reserve_or_quarantine_proxy(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "inputs.json"
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["BA-12345678ABCDEF"],
                "phone": "+38761123456",
                "proxies": [
                    "proxy-a.test:3010:user:password-a",
                    "proxy-b.test:3010:user:password-b",
                ],
                "next_proxy_index": 1,
            }
        ),
        encoding="utf-8",
    )
    observed = {}

    def fake_run(self):
        observed["profile_id"] = self.existing_profile_id
        observed["profile_name"] = self.existing_profile_name
        return {
            "status": "failed",
            "browser_transport": {
                "main_documents": [
                    {"path": "/agreements/approve", "status": 403}
                ]
            },
        }

    monkeypatch.setattr(RoxySignupLab, "run", fake_run)

    result = run_signup_lab_from_file(
        mode="reference",
        input_file=source,
        capture_dir=tmp_path / "capture",
        existing_profile_id="explicit-profile-id",
        existing_profile_name="test",
    )

    state = json.loads(source.read_text(encoding="utf-8"))
    assert state["next_proxy_index"] == 1
    assert "failed_proxy_hashes" not in state
    assert observed == {
        "profile_id": "explicit-profile-id",
        "profile_name": "test",
    }
    assert result["proxy_rotation"]["cursor_advanced"] is False
    assert result["proxy_rotation"]["approval_403_quarantined"] is False
    assert result["proxy_rotation"]["reason"] == "existing_profile_control_uses_persisted_proxy"


def test_approval_403_detection_is_scoped_to_the_approval_document() -> None:
    assert _approval_document_has_status(
        {
            "browser_transport": {
                "main_documents": [
                    {"path": "/agreements/approve", "status": 403},
                    {"path": "/captcha/", "status": 200},
                ]
            }
        },
        403,
    )
    assert not _approval_document_has_status(
        {"browser_transport": {"main_documents": [{"path": "/asset.js", "status": 403}]}},
        403,
    )


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


def test_signup_lab_allows_slow_roxy_profile_startup() -> None:
    config = SimpleNamespace(
        headless=True,
        close_after_capture=True,
        delete_after_capture=True,
        timeout_seconds=12.0,
    )

    _configure_roxy_for_signup_lab(config)

    assert config.headless is False
    assert config.force_open is True
    assert config.close_after_capture is False
    assert config.delete_after_capture is False
    assert config.timeout_seconds == 60.0


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

    integrity = capture.close()

    rows = [json.loads(line) for line in capture.events_path.read_text(encoding="utf-8").splitlines()]
    assert [row["seq"] for row in rows] == [1, 2]
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
    assert integrity == {
        "valid": True,
        "expected_records": 2,
        "physical_lines": 2,
        "valid_json_lines": 2,
        "invalid_json_lines": 0,
        "invalid_line_numbers": [],
        "sequence_contiguous": True,
    }


def test_cdp_capture_serializes_concurrent_jsonl_callbacks(tmp_path) -> None:
    capture = CdpCapture(None, tmp_path / "browser", pause_signup=False)
    thread_count = 8
    events_per_thread = 75

    def write_events(worker: int) -> None:
        for index in range(events_per_thread):
            capture._record(
                "testEvent",
                {"worker": worker, "index": index, "type": "Document"},
            )

    threads = [threading.Thread(target=write_events, args=(worker,)) for worker in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    integrity = capture.close()
    rows = [json.loads(line) for line in capture.events_path.read_text(encoding="utf-8").splitlines()]

    assert integrity["valid"] is True
    assert integrity["expected_records"] == thread_count * events_per_thread
    assert len(rows) == thread_count * events_per_thread
    assert [row["seq"] for row in rows] == list(range(1, len(rows) + 1))
    assert all(row["resource_type"] == "Document" for row in rows)


def test_capture_integrity_rejects_interleaved_or_truncated_json(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"seq":1,"event_kind":"requestWillBeSent"}\n'
        '{"seq":2,"event_kind":"responseReceived"'
        '{"seq":3,"event_kind":"loadingFinished"}\n',
        encoding="utf-8",
    )

    integrity = audit_jsonl_capture(path, expected_records=3)

    assert integrity["valid"] is False
    assert integrity["physical_lines"] == 2
    assert integrity["valid_json_lines"] == 1
    assert integrity["invalid_json_lines"] == 1
    assert integrity["sequence_contiguous"] is False


def test_browser_context_tracks_create_and_open_transport_args() -> None:
    context = BrowserSignupContext(
        browser_create_args=["--disable-http2"],
        browser_open_args=["--disable-http2"],
        http2_disabled_requested=True,
        fingerprint_policy={"name": "legacy-macos15-chrome136", "web_rtc_mode": 0},
    )

    assert context.browser_create_args == context.browser_open_args
    assert context.http2_disabled_requested is True
    assert context.fingerprint_policy["web_rtc_mode"] == 0


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


def test_approval_navigation_stops_at_committed_403() -> None:
    calls = []

    class Page:
        def goto(self, url, **kwargs):
            calls.append((url, kwargs))
            return SimpleNamespace(status=403)

    context = BrowserSignupContext()

    with pytest.raises(RuntimeError, match="ROXY_SIGNUP_CHALLENGED"):
        RoxySignupLab._navigate_to_approval(
            Page(),
            "https://www.paypal.com/agreements/approve?ba_token=REDACTED",
            context,
        )

    assert calls[0][1] == {"wait_until": "commit", "timeout": 45000}
    assert context.challenge_markers == ["approval_http_403"]


def test_manual_navigation_waits_for_cdp_approval_document(tmp_path) -> None:
    capture = SimpleNamespace(main_documents=[])

    class Page:
        waits = 0

        def wait_for_timeout(self, milliseconds):
            self.waits += 1
            capture.main_documents.append(
                {
                    "path": "/agreements/approve",
                    "status": 200,
                    "protocol": "http/1.1",
                }
            )

    lab = object.__new__(RoxySignupLab)
    lab.capture_root = tmp_path
    context = BrowserSignupContext(profile_id="existing-profile")

    lab._wait_for_manual_approval(
        Page(),
        capture,
        context,
        timeout_seconds=1,
    )

    ready = json.loads((tmp_path / "manual_navigation_ready.json").read_text(encoding="utf-8"))
    assert ready["ready"] is True
    assert ready["page"] == "about:blank"
    assert "existing-profile" not in json.dumps(ready)
    assert context.stages[-1] == {
        "time": context.stages[-1]["time"],
        "event": "manual_approval_observed",
        "status": 200,
    }


def test_manual_navigation_stops_on_cdp_approval_403(tmp_path) -> None:
    capture = SimpleNamespace(
        main_documents=[
            {"path": "/agreements/approve", "status": 403, "protocol": "http/1.1"}
        ]
    )
    lab = object.__new__(RoxySignupLab)
    lab.capture_root = tmp_path
    context = BrowserSignupContext(profile_id="existing-profile")

    with pytest.raises(RuntimeError, match="ROXY_SIGNUP_CHALLENGED"):
        lab._wait_for_manual_approval(
            SimpleNamespace(wait_for_timeout=lambda milliseconds: None),
            capture,
            context,
            timeout_seconds=1,
        )

    assert context.challenge_markers == ["approval_http_403"]


def test_same_page_warmup_records_only_cookie_names() -> None:
    calls = []

    class BrowserContext:
        def cookies(self, urls):
            assert urls == ["https://www.paypal.com/"]
            return [
                {"name": "LANG", "value": "secret-language-value"},
                {"name": "datadome", "value": "secret-datadome-value"},
            ]

    class Page:
        url = "https://www.paypal.com/home"
        context = BrowserContext()

        def goto(self, url, **kwargs):
            calls.append((url, kwargs))
            return SimpleNamespace(status=200)

        def wait_for_timeout(self, milliseconds):
            calls.append(("wait", milliseconds))

    context = BrowserSignupContext()
    RoxySignupLab._warm_up_same_page(Page(), context)

    assert calls == [
        ("https://www.paypal.com/", {"wait_until": "commit", "timeout": 45000}),
        ("wait", 5000),
    ]
    assert context.warmup == {
        "enabled": True,
        "status": 200,
        "final_path": "/home",
        "cookie_name_count": 2,
        "cookie_names": ["LANG", "datadome"],
    }
    assert "secret" not in json.dumps(context.warmup)


def test_same_page_warmup_stops_on_terminal_challenge() -> None:
    class BrowserContext:
        def cookies(self, urls):
            return [{"name": "datadome", "value": "secret"}]

    class Page:
        url = "https://www.paypal.com/captcha/"
        context = BrowserContext()

        def goto(self, url, **kwargs):
            return SimpleNamespace(status=403)

        def wait_for_timeout(self, milliseconds):
            return None

    context = BrowserSignupContext()

    with pytest.raises(RuntimeError, match="ROXY_WARMUP_CHALLENGED"):
        RoxySignupLab._warm_up_same_page(Page(), context)

    assert context.challenge_markers == ["warmup_challenged"]
    assert context.warmup["cookie_names"] == ["datadome"]


def test_existing_profile_state_reset_clears_every_store_before_target() -> None:
    calls = []

    class Cdp:
        cookie_reads = 0

        def send(self, method, params=None):
            calls.append((method, params or {}))
            if method == "Network.getAllCookies":
                self.cookie_reads += 1
                if self.cookie_reads == 1:
                    return {"cookies": [{"name": "stale", "value": "secret"}]}
                return {"cookies": []}
            return {}

    class BrowserContext:
        def clear_cookies(self):
            calls.append(("BrowserContext.clear_cookies", {}))

    class Page:
        def goto(self, url, **kwargs):
            calls.append(("Page.goto", {"url": url, **kwargs}))

    context = BrowserSignupContext()
    result = clear_existing_profile_state(Cdp(), BrowserContext(), Page(), context)

    methods = [method for method, _ in calls]
    assert methods[0] == "Page.goto"
    assert "Network.clearBrowserCookies" in methods
    assert "Network.clearBrowserCache" in methods
    assert methods.count("Storage.clearDataForOrigin") == 4
    assert methods.count("DOMStorage.clear") == 8
    assert result["cookies_before_count"] == 1
    assert result["cookies_after_count"] == 0
    assert result["verified"] is True
    assert context.stages[-1]["event"] == "existing_profile_state_reset_complete"


def test_existing_profile_state_reset_rejects_remaining_cookie() -> None:
    class Cdp:
        def send(self, method, params=None):
            if method == "Network.getAllCookies":
                return {"cookies": [{"name": "still-present"}]}
            return {}

    class BrowserContext:
        def clear_cookies(self):
            return None

    class Page:
        def goto(self, url, **kwargs):
            return None

    context = BrowserSignupContext()
    with pytest.raises(RuntimeError, match="ROXY_EXISTING_PROFILE_STATE_RESET_FAILED"):
        clear_existing_profile_state(Cdp(), BrowserContext(), Page(), context)

    assert context.state_reset["verified"] is False
    assert context.state_reset["cookies_after_count"] == 1


def test_failure_screenshot_is_best_effort_with_short_timeout(tmp_path) -> None:
    calls = []

    class Page:
        url = "https://www.paypal.com/captcha/"

        def content(self):
            return "<html>challenge</html>"

        def screenshot(self, **kwargs):
            calls.append(kwargs)

    lab = object.__new__(RoxySignupLab)
    lab.capture_root = tmp_path
    (tmp_path / "browser").mkdir()
    context = BrowserSignupContext()

    lab._capture_failure_page(Page(), context)

    assert calls[0]["timeout"] == 3000
    assert calls[0]["full_page"] is True
    assert context.final_url.endswith("/captcha/")


def test_roxy_window_hold_keeps_same_page_connected() -> None:
    waits = []

    class Page:
        def wait_for_timeout(self, milliseconds):
            waits.append(milliseconds)

    lab = object.__new__(RoxySignupLab)
    lab.window_hold_seconds = 2.5
    context = BrowserSignupContext(profile_id="owned-profile")

    lab._hold_window(Page(), context, reason="failure")

    assert waits == [2500]
    assert context.window_hold_seconds == 2.5
    assert context.window_hold_completed is True
    assert [stage["event"] for stage in context.stages] == [
        "roxy_window_hold_start",
        "roxy_window_hold_end",
    ]
    assert context.stages[-1]["completed"] is True


def test_roxy_window_hold_does_not_mask_original_failure() -> None:
    class ClosedPage:
        def wait_for_timeout(self, milliseconds):
            raise RuntimeError("page closed")

    lab = object.__new__(RoxySignupLab)
    lab.window_hold_seconds = 2.5
    context = BrowserSignupContext(profile_id="owned-profile")

    lab._hold_window(ClosedPage(), context, reason="failure")

    assert context.window_hold_completed is False
    assert context.classification["window_hold_error_type"] == "RuntimeError"
    assert context.stages[-1]["completed"] is False


def test_runtime_gate_failure_holds_window_before_raising() -> None:
    calls = []
    lab = object.__new__(RoxySignupLab)
    lab._hold_window = lambda page, context, reason: calls.append((page, reason))
    page = object()
    context = BrowserSignupContext(runtime_fingerprint={"verified": False})

    with pytest.raises(RuntimeError, match="ROXY_RUNTIME_FINGERPRINT_MISMATCH"):
        lab._require_runtime_identity(page, context)

    assert calls == [(page, "runtime_gate_failure")]


def test_passive_challenge_signals_are_observed_but_not_terminal() -> None:
    lab = object.__new__(RoxySignupLab)
    page = type("Page", (), {
        "url": "https://www.paypal.com/pay",
        "context": type("Context", (), {"cookies": lambda self: [{"name": "tsrce", "value": "authchallengenodeweb"}]})(),
    })()
    capture = type(
        "Capture",
        (),
        {
            "challenge_urls": ["https://www.paypal.com/auth/createchallenge/x/hcaptchapassive.js"],
            "main_documents": [
                {
                    "path": "/web/res/hash/hcaptcha/hcaptchapassive.html",
                    "status": 200,
                }
            ],
        },
    )()

    terminal, observed = lab._challenge_evidence(page, capture, "ordinary pay page")

    assert terminal == []
    assert observed == ["tsrce_authchallenge", "passive_challenge_network"]


def test_approval_403_and_captcha_document_are_terminal_challenge_evidence() -> None:
    lab = object.__new__(RoxySignupLab)
    page = type(
        "Page",
        (),
        {
            "url": "https://www.paypal.com/agreements/approve?ba_token=REDACTED",
            "context": type("Context", (), {"cookies": lambda self: []})(),
        },
    )()
    capture = type(
        "Capture",
        (),
        {
            "challenge_urls": ["https://www.paypal.com/captcha/"],
            "main_documents": [
                {"path": "/agreements/approve", "status": 403},
                {"path": "/captcha/", "status": 200},
            ],
        },
    )()

    terminal, observed = lab._challenge_evidence(page, capture, "")

    assert terminal == ["approval_http_403", "challenge_document"]
    assert observed == ["passive_challenge_network"]


def test_pay_stage_uses_exact_application_email_form() -> None:
    source = Path(__file__).resolve().parents[1].joinpath("paypal/signup_lab.py").read_text(encoding="utf-8")
    pay_block = source.split('elif stage == "pay"', 1)[1].split('elif stage == "contact"', 1)[0]

    assert 'form[data-testid=\"emailForm\"]' in pay_block
    assert 'button[data-testid=\"continueButton\"]' in pay_block
    assert "pay_form_submitted = True" in pay_block
    assert "#loginButton" not in pay_block
    assert "pay_create_account_view_selected" in pay_block


@pytest.mark.parametrize(
    ("status", "body", "url", "expected"),
    [
        (
            200,
            "<html><button>Create an account</button></html>",
            "https://www.paypal.com/agreements/approve?ba_token=BA-REDACTED",
            "approval_ready",
        ),
        (
            403,
            "<html><button>Create an account</button></html>",
            "https://www.paypal.com/agreements/approve?ba_token=BA-REDACTED",
            "approval_challenged",
        ),
        (
            200,
            "<html>Billing agreement has expired</html>",
            "https://www.paypal.com/agreements/approve?ba_token=BA-REDACTED",
            "approval_business_error",
        ),
        (
            0,
            "",
            "https://www.paypal.com/agreements/approve?ba_token=BA-REDACTED",
            "approval_timeout",
        ),
    ],
)
def test_approval_control_classifies_only_the_committed_document(
    status: int,
    body: str,
    url: str,
    expected: str,
) -> None:
    result = classify_approval_document(status, "text/html", body, url)

    assert result["result"] == expected
    assert result["valid"] is (expected == "approval_ready")


def test_approval_cdp_capture_omits_remote_connection_and_secret_values(tmp_path) -> None:
    class Cdp:
        def __init__(self):
            self.handlers = {}

        def send(self, method, params=None):
            assert method in {"Page.enable", "Network.enable"}
            return {}

        def on(self, event, callback):
            self.handlers[event] = callback

    cdp = Cdp()
    observer = ApprovalCdpObserver(cdp, tmp_path / "browser")
    observer.start()
    secret_ba = "BA-SHOULD-NOT-BE-WRITTEN"
    cdp.handlers["Network.requestWillBeSent"](
        {
            "type": "Document",
            "request": {
                "method": "GET",
                "url": (
                    "https://www.paypal.com/agreements/approve?ba_token="
                    f"{secret_ba}"
                ),
                "headers": {"Cookie": "secret-cookie"},
            },
        }
    )
    cdp.handlers["Network.responseReceived"](
        {
            "type": "Document",
            "response": {
                "url": "https://www.paypal.com/agreements/approve",
                "status": 200,
                "mimeType": "text/html",
                "protocol": "http/1.1",
                "remoteIPAddress": "192.0.2.10",
                "remotePort": 443,
            },
        }
    )

    audit = observer.close()
    capture_text = (tmp_path / "browser" / "approval-events.jsonl").read_text(
        encoding="utf-8"
    )

    assert audit["valid"] is True
    assert secret_ba not in capture_text
    assert "secret-cookie" not in capture_text
    assert "remoteIPAddress" not in capture_text
    assert "remotePort" not in capture_text
    assert "192.0.2.10" not in capture_text
    assert '"query_keys": ["ba_token"]' in capture_text


def test_approval_control_three_round_gate_rotates_sid_and_preserves_test_profile(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "inputs.json"
    proxies = [
        "proxy-a.test:3010:user:sid-a",
        "proxy-b.test:3010:user:sid-b",
        "proxy-c.test:3010:user:sid-c",
    ]
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["BA-12345678ABCDEF"],
                "phone": "+38761123456",
                "proxies": proxies,
                "next_proxy_index": 0,
            }
        ),
        encoding="utf-8",
    )
    observed = []

    def fake_run(self):
        observed.append(
            {
                "profile_id": self.existing_profile_id,
                "profile_name": self.existing_profile_name,
                "proxy_hash": _hash(self.proxy_entry.url),
            }
        )
        return {
            "status": "approval_ready",
            "profile_cleanup": "closed_retained",
            "profile_retained": True,
            "browser_transport": {"main_documents": []},
        }

    monkeypatch.setattr(RoxyApprovalControl, "run", fake_run)

    result = run_approval_control_from_file(
        input_file=source,
        capture_dir=tmp_path / "capture",
        rounds=3,
        existing_profile_id="be1f8841bf2beb37d23c1b836784392c",
        existing_profile_name="test",
    )

    assert result["status"] == "approval_batch_ready"
    assert result["approval_ready_count"] == 3
    assert result["all_ready"] is True
    assert len({item["proxy_hash"] for item in observed}) == 3
    assert {item["profile_id"] for item in observed} == {
        "be1f8841bf2beb37d23c1b836784392c"
    }
    assert {item["profile_name"] for item in observed} == {"test"}
    assert json.loads(source.read_text(encoding="utf-8"))["next_proxy_index"] == 0


def test_approval_control_three_round_gate_rejects_one_failed_round(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "inputs.json"
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["BA-12345678ABCDEF"],
                "phone": "+38761123456",
                "proxies": [
                    "proxy-a.test:3010:user:sid-a",
                    "proxy-b.test:3010:user:sid-b",
                    "proxy-c.test:3010:user:sid-c",
                ],
            }
        ),
        encoding="utf-8",
    )
    statuses = iter(["approval_ready", "approval_challenged", "approval_ready"])
    monkeypatch.setattr(
        RoxyApprovalControl,
        "run",
        lambda self: {
            "status": next(statuses),
            "browser_transport": {"main_documents": []},
        },
    )

    result = run_approval_control_from_file(
        input_file=source,
        capture_dir=tmp_path / "capture",
        rounds=3,
        existing_profile_id="be1f8841bf2beb37d23c1b836784392c",
        existing_profile_name="test",
    )

    assert result["status"] == "approval_batch_failed"
    assert result["approval_ready_count"] == 2
    assert result["all_ready"] is False


def test_approval_control_never_deletes_owned_or_existing_profile() -> None:
    run_source = inspect.getsource(RoxyApprovalControl.run)

    assert ".delete_profile(" not in run_source
    assert "client.close_profile(profile_id)" in run_source


def test_existing_ios_profile_detail_recognizes_crios_major() -> None:
    safe = _safe_existing_profile_detail(
        {
            "windowName": "test",
            "coreVersion": "136",
            "os": "IOS",
            "osVersion": "18",
            "userAgent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "CriOS/136.0.7103.93 Mobile/15E148 Safari/604.1"
            ),
        },
        expected_name="test",
    )

    assert safe["user_agent_major"] == "136"
    assert safe["expected_name_verified"] is True
