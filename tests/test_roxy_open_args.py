from types import SimpleNamespace

from paypal.roxy_fingerprint import RoxyApiClient, _roxy_open_args


def test_proxied_roxy_open_disables_http2_once() -> None:
    assert _roxy_open_args("http://user:password@proxy.test:3010") == [
        "--remote-allow-origins=*",
        "--disable-audio-output",
        "--disable-http2",
    ]
    assert _roxy_open_args(
        "http://user:password@proxy.test:3010",
        ["--disable-audio-output", "--disable-http2"],
    ) == ["--disable-audio-output", "--disable-http2"]


def test_unproxied_roxy_open_keeps_http2_available() -> None:
    assert "--disable-http2" not in _roxy_open_args("")
    assert "--disable-http2" not in _roxy_open_args(None)


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
