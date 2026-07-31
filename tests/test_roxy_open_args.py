from types import SimpleNamespace

from paypal.roxy_fingerprint import (
    ROXY_FINGERPRINT_POLICY,
    RoxyApiClient,
    RoxyCaptureConfig,
    _roxy_open_args,
    _roxy_profile_startup_args,
    inspect_roxy_runtime_identity,
    load_roxy_capture_config,
)


def test_proxied_roxy_open_disables_http2_once() -> None:
    assert _roxy_open_args("http://user:password@proxy.test:3010") == [
        "--remote-allow-origins=*",
        "--disable-audio-output",
        "--disable-http2",
        "--window-size=1000,1000",
    ]
    assert _roxy_open_args(
        "http://user:password@proxy.test:3010",
        ["--disable-audio-output", "--disable-http2"],
    ) == ["--disable-audio-output", "--disable-http2", "--window-size=1000,1000"]


def test_unproxied_roxy_open_keeps_http2_available() -> None:
    assert "--disable-http2" not in _roxy_open_args("")
    assert "--disable-http2" not in _roxy_open_args(None)
    assert _roxy_profile_startup_args("") == []
    assert "--window-size=1000,1000" in _roxy_open_args("")


def test_global_roxy_policy_ignores_legacy_fingerprint_overrides(monkeypatch) -> None:
    monkeypatch.setenv("PAYPAL_ROXY_HEADLESS", "1")
    monkeypatch.setenv("PAYPAL_ROXY_CORE_VERSION", "150")
    monkeypatch.setenv("PAYPAL_ROXY_OS", "Windows")
    monkeypatch.setenv("PAYPAL_ROXY_OS_VERSION", "11")
    config = load_roxy_capture_config(proxy_url="")

    assert config.headless is False
    assert config.core_type == "Chrome"
    assert config.core_version == "136"
    assert config.os_name == "macOS"
    assert config.os_version == "15"
    assert config.web_rtc_mode == 0
    assert (config.open_width, config.open_height) == (1000, 1000)
    assert ROXY_FINGERPRINT_POLICY.name == "legacy-macos15-chrome136"


def test_proxied_profile_persists_open_args_before_first_launch() -> None:
    proxy_url = "http://user:password@proxy.test:3010"
    client = RoxyApiClient.__new__(RoxyApiClient)
    client.config = RoxyCaptureConfig(
        api_base="http://127.0.0.1:50000",
        api_key="",
        proxy_url=proxy_url,
        timezone="GMT+01:00 Europe/Sarajevo",
    )
    calls: list[tuple[str, str, dict]] = []
    client.request = lambda method, path, **kwargs: (
        calls.append((method, path, kwargs))
        or {"data": {"dirId": "profile-id"}}
    )

    assert client.create_profile(123, 456) == "profile-id"

    payload = calls[0][2]["json"]
    startup_param = payload["fingerInfo"]["startupParam"]
    assert startup_param.split(";") == _roxy_open_args(proxy_url)
    assert startup_param.count("--disable-http2") == 1
    assert "user" not in startup_param
    assert "password" not in startup_param
    assert "proxy.test" not in startup_param
    assert payload["coreType"] == "Chrome"
    assert payload["coreVersion"] == "136"
    assert payload["os"] == "macOS"
    assert payload["osVersion"] == "15"
    assert payload["fingerInfo"]["webRTC"] == 0
    assert payload["fingerInfo"]["randomFingerprint"] is True
    assert payload["fingerInfo"]["webGLManufacturer"] == ""
    assert payload["fingerInfo"]["webGLRender"] == ""
    assert payload["fingerInfo"]["openWidth"] == "1000"
    assert payload["fingerInfo"]["openHeight"] == "1000"


def test_open_profile_sends_disable_http2_for_proxy() -> None:
    client = RoxyApiClient.__new__(RoxyApiClient)
    client.config = SimpleNamespace(
        proxy_url="http://user:password@proxy.test:3010",
        headless=False,
        close_before_open=False,
        force_open=False,
    )
    calls: list[tuple[str, str, dict]] = []
    client.request = lambda method, path, **kwargs: (
        calls.append((method, path, kwargs))
        or {"data": {"ws": "ws://127.0.0.1/devtools/browser/test"}}
    )

    client.open_profile(123, "profile-id")

    assert calls[0][0:2] == ("POST", "/browser/open")
    assert calls[0][2]["json"]["args"].count("--disable-http2") == 1
    assert calls[0][2]["json"]["args"].count("--window-size=1000,1000") == 1
    assert calls[0][2]["json"]["headless"] is False


def test_randomize_and_freeze_preserves_roxy_noise_and_reapplies_policy() -> None:
    client = RoxyApiClient.__new__(RoxyApiClient)
    client.config = RoxyCaptureConfig(
        api_base="http://127.0.0.1:50000",
        api_key="",
        proxy_url="http://user:password@proxy.test:3010",
        language="en-US",
        display_language="en-US",
        timezone="GMT+01:00 Europe/Sarajevo",
    )
    before = {
        "dirId": "owned-profile",
        "coreType": "Chrome",
        "coreVersion": "136",
        "os": "macOS",
        "osVersion": "15",
        "windowName": "paypal-fp-test",
        "windowRemark": "paypal runtime fingerprint capture",
        "userAgent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/136.0.7103.93 Safari/537.36"
        ),
        "fingerInfo": {
            "canvas": {"noise": "roxy-generated"},
            "audioContext": {"noise": "roxy-generated"},
            "webRTC": 2,
            "randomFingerprint": True,
            "webGLManufacturer": "Google Inc. (Intel Inc.)",
            "webGLRender": "ANGLE Metal Renderer: Intel(R) UHD Graphics 617",
            "hardwareConcurrent": "8",
            "deviceMemory": "8",
        },
    }
    events: list[str] = []
    modified: dict = {}

    client.randomize_profile = lambda workspace_id, dir_id: events.append("random")

    def detail(workspace_id, dir_id):
        events.append("detail")
        if not modified:
            return before
        return {
            "dirId": dir_id,
            "coreType": modified["coreType"],
            "coreVersion": modified["coreVersion"],
            "os": modified["os"],
            "osVersion": modified["osVersion"],
            "userAgent": modified["userAgent"],
            "fingerInfo": modified["fingerInfo"],
        }

    def modify(workspace_id, dir_id, values):
        events.append("modify")
        modified.update(values)

    client.get_profile_detail = detail
    client.modify_profile = modify

    result = client.randomize_and_freeze_profile(123, "owned-profile")

    assert events == ["random", "detail", "modify", "detail"]
    assert result["verification"]["verified"] is True
    assert modified["coreType"] == "Chrome"
    assert modified["coreVersion"] == "136"
    assert modified["os"] == "macOS"
    assert modified["osVersion"] == "15"
    assert "Chrome/136." in modified["userAgent"]
    assert modified["fingerInfo"]["webRTC"] == 0
    assert modified["fingerInfo"]["randomFingerprint"] is False
    assert modified["fingerInfo"]["canvas"] == {"noise": "roxy-generated"}
    assert modified["fingerInfo"]["audioContext"] == {"noise": "roxy-generated"}
    assert modified["fingerInfo"]["webGLManufacturer"] == "Google Inc. (Intel Inc.)"
    assert "Apple M3" not in modified["fingerInfo"]["webGLRender"]


def test_roxy_v4_summary_detail_uses_visible_and_acknowledged_policy_evidence() -> None:
    client = RoxyApiClient.__new__(RoxyApiClient)
    client.config = RoxyCaptureConfig(
        api_base="http://127.0.0.1:50000",
        api_key="",
        proxy_url="http://user:password@proxy.test:3010",
        language="en-US",
        display_language="en-US",
        timezone="GMT+01:00 Europe/Sarajevo",
    )
    generated_ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0.7103.62 Safari/537.36"
    )
    modified: dict = {}
    details = [
        {
            "dirId": "owned-profile",
            "coreVersion": "136",
            "os": "macOS",
            "osVersion": "15.1",
            "userAgent": generated_ua,
        },
        {
            "dirId": "owned-profile",
            "coreVersion": "136",
            "os": "macOS",
            "osVersion": "15.2",
            "userAgent": generated_ua,
        },
    ]
    client.randomize_profile = lambda workspace_id, dir_id: None
    client.get_profile_detail = lambda workspace_id, dir_id: details.pop(0)
    client.modify_profile = lambda workspace_id, dir_id, values: modified.update(values) or {"code": 0}

    result = client.randomize_and_freeze_profile(123, "owned-profile")
    verification = result["verification"]

    assert modified["userAgent"] == generated_ua
    assert verification["verified"] is True
    assert verification["mdf_acknowledged"] is True
    assert verification["detail_finger_info_present"] is False
    assert verification["mismatches"] == []
    assert set(verification["unobservable"]) >= {
        "core_type",
        "web_rtc_mode",
        "random_fingerprint",
        "language",
        "timezone",
    }
    assert verification["observed"]["os_version"] == "15.2"


def test_runtime_identity_verification_uses_cdp_without_webrtc_probe() -> None:
    config = RoxyCaptureConfig(
        api_base="http://127.0.0.1:50000",
        api_key="",
        language="en-US",
        display_language="en-US",
        timezone="GMT+01:00 Europe/Sarajevo",
    )

    class Cdp:
        def send(self, method):
            assert method == "Browser.getVersion"
            return {"product": "Chrome/136.0.7103.93", "protocolVersion": "1.3"}

    class Page:
        def evaluate(self, script):
            assert "RTCPeerConnection" not in script
            assert "candidate" not in script.lower()
            return {
                "userAgent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/136.0.7103.93 Safari/537.36"
                ),
                "platform": "MacIntel",
                "language": "en-US",
                "languages": ["en-US", "en"],
                "timezone": "Europe/Sarajevo",
                "screen": {"width": 1536, "height": 864},
                "window": {
                    "innerWidth": 1000,
                    "innerHeight": 913,
                    "outerWidth": 1000,
                    "outerHeight": 1000,
                },
            }

    verification = inspect_roxy_runtime_identity(Cdp(), Page(), config)

    assert verification["verified"] is True
    assert verification["mismatches"] == []
    assert verification["observed"]["headless_ua"] is False
