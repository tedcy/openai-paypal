import inspect
import json
import threading
import tomllib
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
    _SIGNUP_LAB_NAVIGATION_TIMEOUT_SECONDS,
    _approval_document_has_status,
    _configure_roxy_for_randomized_ios,
    _configure_roxy_for_signup_lab,
    _cold_protocol_ios136_profile,
    _create_dedicated_control_page,
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
from paypal.country import profile_for_country
from paypal.fingerprint import generate_runtime_profile
from paypal.proxy import ProxyEntry
from paypal.traffic_recorder import TrafficRecorder
from tools.compare_paypal_traffic import compare


def test_signup_lab_cli_defaults_to_toml_input_state() -> None:
    source = (Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8")

    assert 'default="var/signup-lab/inputs-ba.toml"' in source


def test_cold_protocol_ios136_profile_preserves_mobile_identity(monkeypatch) -> None:
    monkeypatch.setenv("PAYPAL_RANDOMIZE_BROWSER_PROFILE", "1")
    seed = _cold_protocol_ios136_profile(profile_for_country("BA"))

    runtime = generate_runtime_profile("random", browser_profile=seed)
    profile = runtime["browser_profile"]

    assert profile["chrome_major"] == 136
    assert profile["chrome_full_version"] == "136.0.7103.60"
    assert "CriOS/136.0.7103.60" in profile["user_agent"]
    assert profile["platform"] == "iPhone"
    assert profile["ua_client_hints_enabled"] is False
    assert profile["country"] == "BA"
    assert profile["language"] == "en-BA"
    assert profile["timezone"] == "Europe/Sarajevo"
    assert runtime["screen"]["width"] == 480
    assert runtime["screen"]["height"] == 854
    assert runtime["viewport"] == {"width": 480, "height": 754}


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


def test_signup_lab_inputs_support_toml_and_persist_rotation(tmp_path) -> None:
    source = tmp_path / "inputs.toml"
    first = "proxy-a.test:3010:user:password-a"
    second = "proxy-b.test:3010:user:password-b"
    source.write_text(
        "\n".join(
            [
                'ba_tokens = ["BA-12345678ABCDEF", "BA-87654321FEDCBA"]',
                'phone = "+38761123456"',
                f'proxies = ["{first}", "{second}"]',
                "failed_proxy_hashes = []",
                "next_ba_index = 1",
                "next_proxy_index = 0",
                "",
            ]
        ),
        encoding="utf-8",
    )

    loaded = SignupLabInputs.load(source)
    _, ba_token, selected_proxy, rotation = SignupLabInputs.reserve_for_profile(source)
    first_hash, added = SignupLabInputs.quarantine_proxy(source, first)
    persisted = tomllib.loads(source.read_text(encoding="utf-8"))

    assert loaded.selection() == ("BA-87654321FEDCBA", first)
    assert ba_token == "BA-87654321FEDCBA"
    assert selected_proxy == first
    assert rotation["next_proxy_index"] == 1
    assert added is True
    assert persisted["next_ba_index"] == 1
    assert persisted["next_proxy_index"] == 1
    assert persisted["failed_proxy_hashes"] == [first_hash]
    assert persisted["proxies"] == [first, second]


def test_signup_lab_inputs_reject_unknown_file_format(tmp_path) -> None:
    source = tmp_path / "inputs.yaml"
    source.write_text("ba_tokens: []\n", encoding="utf-8")

    with pytest.raises(ValueError, match=".json or .toml"):
        SignupLabInputs.load(source)


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


@pytest.mark.parametrize(
    "transport",
    ["httpx", "httpx-http1", "curl-chrome", "curl-chrome-http1"],
)
def test_signup_lab_accepts_explicit_protocol_transports(
    tmp_path, transport: str
) -> None:
    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / transport,
        protocol_transport=transport,
    )

    assert lab.protocol_transport == transport


def test_signup_lab_http1_transports_are_explicit() -> None:
    source = inspect.getsource(RoxySignupLab._protocol_handoff)

    assert 'impersonate="chrome136"' in source
    assert "CurlHttpVersion.V1_1" in source
    assert 'self.protocol_transport == "httpx"' in source


def test_handoff_preserves_captured_cookie_header_and_order(tmp_path) -> None:
    paused = {
        "request": {
            "url": "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
            "headers": {
                "Host": "www.paypal.com",
                "cookie": "second=2; first=1",
                "Referer": "https://www.paypal.com/pay",
            },
        }
    }

    headers = RoxySignupLab._handoff_headers(
        paused,
        [{"name": "fallback", "value": "unused"}],
    )

    assert headers["cookie"] == "second=2; first=1"
    assert "Cookie" not in headers
    assert "Host" not in headers


def test_handoff_cookie_snapshot_fallback_preserves_snapshot_order() -> None:
    headers = RoxySignupLab._handoff_headers(
        {
            "request": {
                "url": "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
                "headers": {},
            }
        },
        [
            {"name": "second", "value": "2"},
            {"name": "first", "value": "1"},
        ],
    )

    assert headers["Cookie"] == "second=2; first=1"


def test_handoff_browser_jar_removes_captured_cookie_header() -> None:
    headers = RoxySignupLab._handoff_headers(
        {
            "request": {
                "url": "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
                "headers": {
                    "cookie": "captured=browser",
                    "Referer": "https://www.paypal.com/pay",
                },
            }
        },
        [{"name": "jar", "value": "value"}],
        cookie_source="browser-jar",
    )

    assert not any(key.lower() == "cookie" for key in headers)
    assert headers["Referer"] == "https://www.paypal.com/pay"


def test_handoff_generated_ios_headers_keep_only_dynamic_referer() -> None:
    headers = RoxySignupLab._handoff_headers(
        {
            "request": {
                "url": "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
                "headers": {
                    "Accept": "captured-accept",
                    "Referer": "https://www.paypal.com/pay?token=EC-12345678",
                    "User-Agent": "captured-runtime-ua",
                    "X-Captured-Only": "remove-me",
                },
            }
        },
        [],
        cookie_source="browser-jar",
        header_source="generated-ios136",
    )

    assert headers == {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "CriOS/136.0.7103.60 Mobile/15E148 Safari/537.36"
        ),
        "Referer": "https://www.paypal.com/pay?token=EC-12345678",
    }


def test_handoff_browser_cookie_snapshot_populates_scoped_client_jar() -> None:
    calls = []

    class CookieJar:
        @staticmethod
        def set(name, value, **kwargs):
            calls.append((name, value, kwargs))

    populated = RoxySignupLab._populate_cookie_jar(
        CookieJar(),
        [
            {
                "name": "session",
                "value": "value",
                "domain": ".paypal.com",
                "path": "/checkoutweb",
                "secure": True,
            },
            {"name": "", "value": "ignored"},
        ],
    )

    assert populated == 1
    assert calls == [
        (
            "session",
            "value",
            {"domain": ".paypal.com", "path": "/checkoutweb", "secure": True},
        )
    ]


@pytest.mark.parametrize("cookie_source", ["captured-header", "browser-jar"])
def test_signup_lab_accepts_explicit_handoff_cookie_sources(
    tmp_path, cookie_source: str
) -> None:
    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / cookie_source,
        handoff_cookie_source=cookie_source,
    )

    assert lab.handoff_cookie_source == cookie_source


@pytest.mark.parametrize("header_source", ["captured", "generated-ios136"])
def test_signup_lab_accepts_explicit_handoff_header_sources(
    tmp_path, header_source: str
) -> None:
    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / header_source,
        handoff_header_source=header_source,
    )

    assert lab.handoff_header_source == header_source


@pytest.mark.parametrize("url_source", ["captured", "session-state"])
def test_signup_lab_accepts_explicit_handoff_url_sources(
    tmp_path, url_source: str
) -> None:
    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / url_source,
        handoff_url_source=url_source,
    )

    assert lab.handoff_url_source == url_source


def test_session_state_handoff_rebuilds_bosnia_signup_url_and_referer(
    tmp_path,
) -> None:
    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / "session-state",
        handoff_url_source="session-state",
    )

    signup_url, referer = lab._session_state_handoff_target(
        "https://www.paypal.com/checkoutweb/signup"
        "?ssrt=1785555248159&locale.x=wrong&country.x=US"
        "&ba_token=BA-CAPTURED123456&token=EC-6T5956334X260411R"
    )

    assert signup_url == (
        "https://www.paypal.com/checkoutweb/signup"
        "?ssrt=1785555248159&ul=1&modxo_redirect_reason=guest_user"
        "&locale.x=en_BA&country.x=BA&ba_token=BA-12345678ABCDEF"
        "&token=EC-6T5956334X260411R&rcache=1"
    )
    assert referer == (
        "https://www.paypal.com/pay"
        "?ssrt=1785555248159&token=BA-12345678ABCDEF&ul=1"
    )


def test_session_state_handoff_requires_ec_and_ssrt(tmp_path) -> None:
    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / "missing-state",
        handoff_url_source="session-state",
    )

    with pytest.raises(RuntimeError, match="ROXY_EC_TOKEN_MISSING"):
        lab._session_state_handoff_target(
            "https://www.paypal.com/checkoutweb/signup?ssrt=1785555248159"
        )
    with pytest.raises(RuntimeError, match="ROXY_SSRT_MISSING"):
        lab._session_state_handoff_target(
            "https://www.paypal.com/checkoutweb/signup?token=EC-12345678"
        )


def test_requested_handoff_sources_are_recorded_before_navigation() -> None:
    source = inspect.getsource(RoxySignupLab.run)

    assert "protocol_cookie_source=self.handoff_cookie_source" in source
    assert "protocol_header_source=self.handoff_header_source" in source
    assert "protocol_url_source=self.handoff_url_source" in source


def test_cli_exposes_session_state_handoff_url_source() -> None:
    source = (Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8")

    assert '"--handoff-url-source"' in source
    assert 'choices=["captured", "session-state"]' in source
    assert "handoff_url_source=args.handoff_url_source" in source


def test_paused_handoff_runs_protocol_before_resolution_without_page_access(
    tmp_path,
    monkeypatch,
) -> None:
    calls = []

    class Capture:
        paused_signup = {
            "request": {
                "url": (
                    "https://www.paypal.com/checkoutweb/signup"
                    "?token=EC-12345678&ssrt=123&ctxId=context"
                ),
                "headers": {"Cookie": "session=browser"},
            }
        }

        @staticmethod
        def pause_elapsed_ms():
            return 17

        @staticmethod
        def fail_paused_signup():
            calls.append("resolve")
            return "failed_aborted"

    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / "capture",
        protocol_transport="curl-chrome-http1",
    )
    context = BrowserSignupContext()

    def protocol_handoff(paused, cookies, output):
        calls.append("protocol")
        assert context.protocol_request_started is True
        assert context.signup_request_paused is True
        return {
            "status": 200,
            "classification": {"valid": True, "content_type": "text/html"},
        }

    monkeypatch.setattr(lab, "_protocol_handoff", protocol_handoff)

    lab._execute_paused_handoff(Capture(), [], context)

    assert calls == ["protocol", "resolve"]
    assert context.pause_to_protocol_ms == 17
    assert context.protocol_request_completed is True
    assert context.protocol_response_status == 200
    assert context.paused_request_resolution == "failed_aborted"
    assert context.ec_token == "EC-12345678"
    assert "page." not in inspect.getsource(RoxySignupLab._execute_paused_handoff)


def test_paused_handoff_resolves_request_when_protocol_raises(
    tmp_path,
    monkeypatch,
) -> None:
    calls = []

    class Capture:
        paused_signup = {
            "request": {
                "url": "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
                "headers": {},
            }
        }

        @staticmethod
        def pause_elapsed_ms():
            return 3

        @staticmethod
        def fail_paused_signup():
            calls.append("resolve")
            return "failed_aborted"

    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / "capture",
    )
    context = BrowserSignupContext()

    def protocol_handoff(paused, cookies, output):
        calls.append("protocol")
        raise RuntimeError("protocol timeout")

    monkeypatch.setattr(lab, "_protocol_handoff", protocol_handoff)

    with pytest.raises(RuntimeError, match="protocol timeout"):
        lab._execute_paused_handoff(Capture(), [], context)

    assert calls == ["protocol", "resolve"]
    assert context.protocol_request_completed is False
    assert context.handoff_error_stage == "protocol_request"
    assert context.paused_request_resolution == "failed_aborted"


def test_handoff_defaults_to_thirty_second_headed_window_hold(tmp_path) -> None:
    lab = RoxySignupLab(
        mode="handoff",
        ba_token="BA-12345678ABCDEF",
        phone="+38761123456",
        proxy_line="proxy.test:3010:user:password",
        capture_root=tmp_path / "capture",
    )

    assert lab.window_hold_seconds == 30.0


def test_signup_navigation_budget_covers_slow_ctf_page_transitions() -> None:
    assert _SIGNUP_LAB_NAVIGATION_TIMEOUT_SECONDS == 300.0
    source = inspect.getsource(RoxySignupLab._drive_to_signup)
    assert "_SIGNUP_LAB_NAVIGATION_TIMEOUT_SECONDS" in source


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


def test_signup_navigation_uses_locale_independent_create_account_control() -> None:
    source = inspect.getsource(RoxySignupLab._drive_to_signup)

    assert source.index("if capture.paused_signup is not None") < source.index(
        "page.wait_for_timeout(350)"
    )
    assert 'form[data-testid="create-account-form"]' in source
    assert 'button[type="submit"]' in source
    assert '"element => element.click()"' in source
    assert source.count("no_wait_after=True") >= 1
    assert "english-text-fallback" in source


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


def test_signup_lab_new_profiles_use_randomized_ios_lifecycle() -> None:
    config = SimpleNamespace(
        core_type="Chrome",
        core_version="136",
        os_name="macOS",
        os_version="15",
        web_rtc_mode=1,
        headless=True,
        force_open=True,
        close_before_open=True,
        close_after_capture=True,
        delete_after_capture=True,
        timeout_seconds=12.0,
    )

    _configure_roxy_for_randomized_ios(config)

    assert config.core_type == "Chrome"
    assert config.core_version == "136"
    assert config.os_name == "IOS"
    assert config.os_version == "18"
    assert config.web_rtc_mode == 0
    assert config.headless is False
    assert config.force_open is False
    assert config.close_before_open is False
    assert config.close_after_capture is False
    assert config.delete_after_capture is False
    assert config.timeout_seconds == 60.0

    source = inspect.getsource(RoxySignupLab.run)
    assert "preserve_randomized=True" in source
    assert "refresh_host_identity=True" in source
    assert "open_existing_profile_preserving_settings" in source
    assert "preserve_randomized=not existing_control" in source
    assert "_create_dedicated_control_page" in source


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
    healthy_with_passive_helpers = classify_signup_document(
        200,
        "text/html",
        "<html><script>window.__INITIAL_DATA__={}</script>"
        "<script src='/authchallenge/hcaptcha-passive.js'></script>"
        "<div>checkoutweb signup</div></html>",
        "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
    )
    challenged_200 = classify_signup_document(
        200,
        "text/html",
        "<html>DataDome Security Challenge CAPTCHA</html>",
        "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
    )

    assert valid["valid"] is True
    assert challenged["valid"] is False
    assert set(challenged["challenge_markers"]) >= {"datadome", "security challenge"}
    assert challenged["terminal_challenge_markers"]
    assert healthy_with_passive_helpers["valid"] is True
    assert set(healthy_with_passive_helpers["passive_challenge_markers"]) == {
        "authchallenge",
        "captcha",
    }
    assert healthy_with_passive_helpers["terminal_challenge_markers"] == []
    assert challenged_200["valid"] is False
    assert challenged_200["terminal_challenge_markers"]


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


def test_lab_raw_recorder_bounds_artifact_names_for_long_query_urls(tmp_path) -> None:
    recorder = TrafficRecorder(tmp_path / "protocol", lab_raw=True)
    raw_token = "BA-1234567890ABCDEF"
    long_url = (
        "https://www.paypal.com/pay?ssrt=1234567890"
        f"&token={raw_token}&ul=1&ctxId=" + ("x" * 180)
        + "&paypal_client_cfci=modxo_vaulted_not_recurring-Pay_With_Card"
    )
    request_id = recorder.record_request(
        "POST",
        long_url,
        {"data": {"formName": "createAccountAction"}},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    recorder.record_response(
        request_id,
        "POST",
        long_url,
        httpx.Response(200, text="server action response"),
    )
    recorder.close()

    artifacts = [
        *recorder.requests_dir.iterdir(),
        *recorder.bodies_dir.iterdir(),
    ]
    assert len(artifacts) == 2
    assert all(len(path.name) < 96 for path in artifacts)
    assert all(raw_token not in path.name for path in artifacts)
    assert all(path.is_file() for path in artifacts)
    assert raw_token in recorder.events_file.read_text(encoding="utf-8")


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
    assert 'selected_by = "create-account-form-dom-click"' in pay_block
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


def test_approval_control_creates_dedicated_page_before_closing_startup_pages() -> None:
    events = []

    class Page:
        def __init__(self, name):
            self.name = name

        def close(self):
            events.append(("close", self.name))

    startup_one = Page("startup-one")
    startup_two = Page("startup-two")
    dedicated = Page("dedicated")

    class Context:
        pages = [startup_one, startup_two]

        def new_page(self):
            events.append(("create", "dedicated"))
            return dedicated

    page, summary = _create_dedicated_control_page(Context())

    assert page is dedicated
    assert events == [
        ("create", "dedicated"),
        ("close", "startup-one"),
        ("close", "startup-two"),
    ]
    assert summary == {
        "startup_page_count": 2,
        "startup_pages_closed": 2,
        "startup_page_close_failures": [],
        "dedicated_page_created": True,
    }
