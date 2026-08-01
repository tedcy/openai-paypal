from pathlib import Path

import pytest

from paypal.proxy import build_automatic_proxy_config


def _write_proxy_template(path: Path, proxy: str) -> None:
    path.write_text(
        'ba_tokens = ["BA-IGNORED"]\n'
        'phone = "+38761123456"\n'
        f'proxies = ["{proxy}"]\n'
        'next_proxy_index = 99\n',
        encoding="utf-8",
    )


def test_automatic_proxy_rewrites_country_and_sid_without_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "inputs-ba.toml"
    _write_proxy_template(
        source,
        "proxy.test:3010:account-region-BA-sid-OldSid01-t-120:proxy-password",
    )
    monkeypatch.setenv(
        "PAYPAL_PROXY_URL",
        "http://environment-user:environment-password@environment.test:9999",
    )
    monkeypatch.setenv(
        "PAYPAL_PROXY_POOL",
        "pool.test:8888:pool-user:pool-password",
    )
    monkeypatch.setattr("paypal.proxy.secrets.choice", lambda alphabet: "N")

    config = build_automatic_proxy_config(
        "US",
        source_path=source,
    )

    assert config.enabled is True
    assert config.entry is not None
    assert config.entry.host == "proxy.test"
    assert config.entry.port == 3010
    assert config.entry.username == "account-region-US-sid-NNNNNNNN-t-120"
    assert config.entry.password == "proxy-password"
    assert "environment.test" not in config.url
    assert "pool.test" not in config.url
    assert "region=US" in config.label
    assert "sid=NNNNNNNN" in config.label
    assert "proxy-password" not in config.label
    assert "account" not in config.label


@pytest.mark.parametrize("country", ["BR", "TH", "BA", "US"])
def test_automatic_proxy_supports_all_web_countries(
    tmp_path: Path,
    country: str,
) -> None:
    source = tmp_path / "inputs-ba.toml"
    _write_proxy_template(
        source,
        "proxy.test:3010:account-region-BA-sid-OldSid01-t-120:secret",
    )

    config = build_automatic_proxy_config(
        country,
        source_path=source,
        sid="Route123",
    )

    assert config.entry is not None
    assert f"-region-{country}-sid-Route123-t-120" in config.entry.username


def test_automatic_proxy_rejects_missing_or_unrouted_template(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="自动代理模板不存在"):
        build_automatic_proxy_config(
            "BA",
            source_path=tmp_path / "missing.toml",
            sid="Route123",
        )

    source = tmp_path / "inputs-ba.toml"
    _write_proxy_template(source, "proxy.test:3010:plain-user:secret")
    with pytest.raises(ValueError, match="region-XX-sid"):
        build_automatic_proxy_config(
            "BA",
            source_path=source,
            sid="Route123",
        )
