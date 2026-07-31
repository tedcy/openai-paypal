from types import SimpleNamespace

from paypal.roxy_fingerprint import (
    ROXY_FINGERPRINT_POLICY,
    RoxyApiClient,
    RoxyCaptureConfig,
    _roxy_open_args,
    _roxy_profile_startup_args,
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
