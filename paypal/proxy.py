"""Proxy helpers for outbound HTTP requests.

Supports custom environment proxy lines in the form:
    host:port:username:password
and direct proxy URLs in the form:
    http://username:password@host:port

Both formats are converted to httpx-compatible proxy URLs.

The Web route additionally derives a country-specific username and fresh SID
from a Git-ignored local TOML template; it does not consume proxy environment
variables or client-supplied proxy values.
"""
from __future__ import annotations

import os
import random
import re
import secrets
import string
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

_TRUE_VALUES = {"1", "true", "yes", "on", "enable", "enabled", "y"}
_FALSE_VALUES = {"0", "false", "no", "off", "disable", "disabled", "n", ""}
_ROUTED_PROXY_USERNAME_RE = re.compile(
    r"^(?P<prefix>.+-region-)(?P<region>[A-Za-z]{2})"
    r"(?P<middle>-sid-)(?P<sid>[A-Za-z0-9]+)(?P<suffix>-t-\d+.*)$"
)
_PROXY_SID_ALPHABET = string.ascii_letters + string.digits
DEFAULT_WEB_PROXY_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1] / "var" / "signup-lab" / "inputs-ba.toml"
)


def _load_dotenv_value(name: str) -> str:
    """Read a single value from local .env without an extra dependency."""
    if os.getenv(name):
        return os.getenv(name, "").strip()
    roots = [Path.cwd(), Path(__file__).resolve().parents[1]]
    seen: set[Path] = set()
    for root in roots:
        env_path = root / ".env"
        if env_path in seen or not env_path.is_file():
            continue
        seen.add(env_path)
        try:
            for raw in env_path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key.strip() != name:
                    continue
                value = value.strip().strip('"').strip("'")
                os.environ.setdefault(name, value)
                return value
        except Exception:
            continue
    return ""


@dataclass(frozen=True)
class ProxyEntry:
    host: str
    port: int
    username: str
    password: str
    scheme: str = "http"

    @classmethod
    def parse(cls, raw: str) -> "ProxyEntry":
        value = (raw or "").strip()
        if not value:
            raise ValueError("代理配置为空")

        # Already a URL.  This path is mainly for env overrides such as
        # PAYPAL_PROXY_URL=http://user:pass@host:port.
        if "://" in value:
            from urllib.parse import urlsplit, unquote

            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https", "socks5", "socks5h"}:
                raise ValueError(f"不支持的代理协议：{parsed.scheme}")
            if not parsed.hostname or not parsed.port:
                raise ValueError("代理 URL 必须包含 host 和 port")
            return cls(
                host=parsed.hostname,
                port=int(parsed.port),
                username=unquote(parsed.username or ""),
                password=unquote(parsed.password or ""),
                scheme=parsed.scheme,
            )

        parts = value.split(":", 3)
        if len(parts) != 4:
            raise ValueError("代理格式应为 host:port:username:password")
        host, port_text, username, password = [part.strip() for part in parts]
        if not host:
            raise ValueError("代理 host 不能为空")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError("代理 port 必须是数字") from exc
        if not (1 <= port <= 65535):
            raise ValueError("代理 port 超出范围")
        if not username or not password:
            raise ValueError("代理 username/password 不能为空")
        return cls(host=host, port=port, username=username, password=password)

    @property
    def url(self) -> str:
        user = quote(self.username, safe="")
        password = quote(self.password, safe="")
        auth = f"{user}:{password}@" if self.username or self.password else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    @property
    def masked(self) -> str:
        auth = "***:***@" if self.username or self.password else ""
        label = f"{self.scheme}://{auth}{self.host}:{self.port}"
        routed = _ROUTED_PROXY_USERNAME_RE.fullmatch(self.username)
        if routed:
            label += (
                f" [region={routed.group('region').upper()} "
                f"sid={routed.group('sid')}]"
            )
        return label


@dataclass(frozen=True)
class ProxyConfig:
    enabled: bool
    entry: ProxyEntry | None = None

    @property
    def url(self) -> str | None:
        return self.entry.url if self.enabled and self.entry else None

    @property
    def label(self) -> str:
        if not self.enabled or not self.entry:
            return "代理关闭"
        return self.entry.masked


def parse_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in _TRUE_VALUES:
        return True
    if text in _FALSE_VALUES:
        return False
    return default


def _split_pool(raw: str) -> list[str]:
    lines: list[str] = []
    for item in (raw or "").replace(",", "\n").splitlines():
        item = item.strip()
        if item and not item.startswith("#"):
            lines.append(item)
    return lines


def load_proxy_pool() -> list[str]:
    env_url = _load_dotenv_value("PAYPAL_PROXY_URL")
    if env_url:
        return [env_url]

    env_pool = _split_pool(_load_dotenv_value("PAYPAL_PROXY_POOL"))
    if env_pool:
        return env_pool

    return []


def choose_proxy_entry(pool: Iterable[str] | None = None, index: int | None = None) -> ProxyEntry:
    entries = list(pool if pool is not None else load_proxy_pool())
    if not entries:
        raise ValueError("未配置代理池")
    if index is not None:
        if index < 0 or index >= len(entries):
            raise ValueError(f"代理序号超出范围：{index}，可用范围 0-{len(entries) - 1}")
        raw = entries[index]
    else:
        raw = random.choice(entries)
    return ProxyEntry.parse(raw)


def _fresh_proxy_sid(length: int = 8) -> str:
    return "".join(secrets.choice(_PROXY_SID_ALPHABET) for _ in range(length))


def load_automatic_proxy_template(
    source_path: str | Path | None = None,
) -> ProxyEntry:
    """Load the local proxy seed without consulting environment variables.

    The existing Signup Lab input remains Git-ignored and already contains the
    provider account/password.  Web reads only its first proxy as a credential
    template; BA tokens, phone and cursor state are never imported.
    """
    path = Path(source_path or DEFAULT_WEB_PROXY_TEMPLATE_PATH).expanduser()
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ValueError(f"自动代理模板不存在：{path}") from exc
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"自动代理模板 TOML 无效：{path}") from exc
    proxies = data.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        raise ValueError("自动代理模板缺少 proxies 列表")
    template = str(proxies[0] or "").strip()
    if not template:
        raise ValueError("自动代理模板的第一条代理为空")
    return ProxyEntry.parse(template)


def build_automatic_proxy_config(
    country: str,
    *,
    source_path: str | Path | None = None,
    sid: str | None = None,
) -> ProxyConfig:
    """Generate one country-routed proxy with a fresh provider SID."""
    region = str(country or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", region):
        raise ValueError("自动代理国家必须是两位国家码")
    session_id = str(sid or _fresh_proxy_sid()).strip()
    if not re.fullmatch(r"[A-Za-z0-9]{4,32}", session_id):
        raise ValueError("自动代理 SID 必须是 4-32 位字母或数字")

    template = load_automatic_proxy_template(source_path)
    routed = _ROUTED_PROXY_USERNAME_RE.fullmatch(template.username)
    if routed is None:
        raise ValueError(
            "自动代理用户名必须包含 region-XX-sid-XXXXXXXX-t-N 结构"
        )
    username = (
        f"{routed.group('prefix')}{region}{routed.group('middle')}"
        f"{session_id}{routed.group('suffix')}"
    )
    return ProxyConfig(
        enabled=True,
        entry=ProxyEntry(
            host=template.host,
            port=template.port,
            username=username,
            password=template.password,
            scheme=template.scheme,
        ),
    )


def build_proxy_config(
    enabled: bool | None = None,
    index: int | None = None,
    proxy_url: str | None = None,
) -> ProxyConfig:
    """Return a selected proxy config.

    enabled=None means use config/env default.  If disabled, no proxy is selected.
    proxy_url is a per-run custom/chained proxy URL or host:port:user:pass line.
    When enabled is None, providing proxy_url implicitly enables the proxy.
    """
    custom_proxy = (proxy_url or "").strip()
    if enabled is None:
        # Env can override the default at process startup without code changes.
        should_enable = bool(custom_proxy) or parse_bool(_load_dotenv_value("PAYPAL_PROXY_ENABLED"), False)
    else:
        # Explicit CLI/API choices must win so the proxy can be toggled dynamically.
        should_enable = bool(enabled)
    if not should_enable:
        return ProxyConfig(enabled=False)
    if custom_proxy:
        return ProxyConfig(enabled=True, entry=ProxyEntry.parse(custom_proxy))
    return ProxyConfig(enabled=True, entry=choose_proxy_entry(index=index))
