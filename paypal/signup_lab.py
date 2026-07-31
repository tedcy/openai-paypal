"""Roxy/browser reference and protocol handoff lab for checkout signup.

This module deliberately stops at the signup document.  It never submits the
signup form, sends an OTP, adds a funding instrument, or authorizes an
agreement.  It also has no endpoint discovery: CDP comes only from the Roxy
Local API response.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import httpx
from loguru import logger

from config import BROWSER_PROFILE
from paypal.country import browser_profile_for, parse_ba_token, profile_for_phone
from paypal.proxy import ProxyEntry
from paypal.roxy_fingerprint import (
    RoxyApiClient,
    RoxyFingerprintError,
    _connect_over_cdp,
    _roxy_open_args,
    load_roxy_capture_config,
)
from paypal.traffic_recorder import TrafficRecorder, clear_current_traffic_recorder, set_current_traffic_recorder

_CHALLENGE_MARKERS = (
    "authchallenge",
    "datadome",
    "captcha",
    "security challenge",
    "access denied",
)
_INVALID_BA_MARKERS = (
    "invalid billing agreement",
    "billing agreement is invalid",
    "billing agreement has expired",
    "invalid ba token",
    "expired ba token",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash(value: object) -> str:
    raw = value if isinstance(value, bytes) else str(value or "").encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _append_jsonl(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, default=str) + "\n")


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:100] or "body"


def _stage_timing_summary(stages: list[dict[str, Any]]) -> dict[str, Any]:
    parsed: list[tuple[datetime, str]] = []
    for item in stages:
        raw = str(item.get("time") or "")
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        parsed.append((stamp, str(item.get("event") or "unknown")))
    if not parsed:
        return {"total_elapsed_ms": 0, "milestones": []}
    started = parsed[0][0]
    return {
        "total_elapsed_ms": max(0, int((parsed[-1][0] - started).total_seconds() * 1000)),
        "milestones": [
            {"event": event, "elapsed_ms": max(0, int((stamp - started).total_seconds() * 1000))}
            for stamp, event in parsed
        ],
    }


def classify_signup_document(status: int, content_type: str, body: str, url: str) -> dict[str, Any]:
    lowered = (body or "").lower()
    challenge = [marker for marker in _CHALLENGE_MARKERS if marker in lowered]
    invalid_ba = [marker for marker in _INVALID_BA_MARKERS if marker in lowered]
    signup_shape = any(
        marker in lowered
        for marker in ("__initial_data__", "checkoutweb", "weasley", "signup")
    )
    valid = (
        status == 200
        and "text/html" in (content_type or "").lower()
        and "/checkoutweb/signup" in (url or "")
        and signup_shape
        and not challenge
    )
    return {
        "valid": valid,
        "status": status,
        "content_type": content_type,
        "bytes": len((body or "").encode("utf-8", errors="replace")),
        "body_sha256": hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest(),
        "challenge_markers": challenge,
        "invalid_ba_markers": invalid_ba,
        "signup_shape": signup_shape,
    }


@dataclass(slots=True)
class SignupLabInputs:
    ba_tokens: list[str]
    phone: str
    proxies: list[str]
    next_ba_index: int = 0
    next_proxy_index: int = 0

    @classmethod
    def load(cls, path: str | Path) -> "SignupLabInputs":
        source = Path(path).expanduser().resolve()
        data = json.loads(source.read_text(encoding="utf-8-sig"))
        ba_values = data.get("ba_tokens") or data.get("ba_urls") or []
        tokens = [parse_ba_token(str(item)) for item in ba_values]
        phone = str(data.get("phone") or "").strip()
        profile_for_phone(phone)
        proxies = [str(item).strip() for item in data.get("proxies", []) if str(item).strip()]
        if not tokens:
            raise ValueError("signup lab input requires at least one BA token")
        if not proxies:
            raise ValueError("signup lab input requires at least one proxy")
        for proxy in proxies:
            ProxyEntry.parse(proxy)
        return cls(
            ba_tokens=tokens,
            phone=phone,
            proxies=proxies,
            next_ba_index=int(data.get("next_ba_index") or 0) % len(tokens),
            next_proxy_index=int(data.get("next_proxy_index") or 0) % len(proxies),
        )

    def selection(self) -> tuple[str, str]:
        return (
            self.ba_tokens[self.next_ba_index % len(self.ba_tokens)],
            self.proxies[self.next_proxy_index % len(self.proxies)],
        )


@dataclass(slots=True)
class BrowserSignupContext:
    status: str = "running"
    final_url: str = ""
    http_status: int = 0
    content_type: str = ""
    ec_token: str = ""
    ssrt: str = ""
    ctx_id: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    stages: list[dict[str, Any]] = field(default_factory=list)
    challenge_markers: list[str] = field(default_factory=list)
    classification: dict[str, Any] = field(default_factory=dict)
    workspace_id: int = 0
    project_id: int = 0
    profile_id: str = ""
    profile_retained: bool = False
    same_context_page: bool = True
    browser_open_args: list[str] = field(default_factory=list)
    http2_disabled_requested: bool = False
    transport_summary: dict[str, Any] = field(default_factory=dict)
    stage_timing: dict[str, Any] = field(default_factory=dict)
    ui_generation: str = "unknown"


def classify_signup_ui(url: str) -> str:
    """Classify the checkout surface without interacting with signup fields."""
    path = urllib.parse.urlsplit(url or "").path.lower().rstrip("/")
    if path == "/checkoutweb/signup" or path.startswith("/checkoutweb/signup/"):
        return "legacy_checkoutweb"
    if path == "/pay/checkout/signup/contact" or path.startswith(
        "/pay/checkout/signup/contact/"
    ):
        return "contact_signup"
    return "unknown"


class CdpCapture:
    def __init__(self, cdp: Any, root: Path, *, pause_signup: bool):
        self.cdp = cdp
        self.root = root
        self.events_path = root / "network" / "events.jsonl"
        self.bodies_dir = root / "network" / "bodies"
        self.pause_signup = pause_signup
        self.paused_signup: dict[str, Any] | None = None
        self.requests: dict[str, dict[str, Any]] = {}
        self.extra_headers: dict[str, dict[str, Any]] = {}
        self.responses: dict[str, dict[str, Any]] = {}
        self.challenge_urls: list[str] = []
        self.request_event_count = 0
        self.response_event_count = 0
        self.loading_failed_count = 0
        self.https_protocol_counts: dict[str, int] = {}
        self.main_documents: list[dict[str, Any]] = []

    def start(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.bodies_dir.mkdir(parents=True, exist_ok=True)
        self.cdp.send("Network.enable", {"maxTotalBufferSize": 100_000_000, "maxResourceBufferSize": 20_000_000})
        self.cdp.on("Network.requestWillBeSent", self._request)
        self.cdp.on("Network.requestWillBeSentExtraInfo", self._request_extra)
        self.cdp.on("Network.responseReceived", self._response)
        self.cdp.on("Network.responseReceivedExtraInfo", self._response_extra)
        self.cdp.on("Network.loadingFinished", self._finished)
        self.cdp.on("Network.loadingFailed", self._loading_failed)
        if self.pause_signup:
            self.cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*://*/checkoutweb/signup*", "resourceType": "Document", "requestStage": "Request"}]})
            self.cdp.on("Fetch.requestPaused", self._paused)

    def _record(self, kind: str, event: Mapping[str, Any]) -> None:
        payload = dict(event)
        resource_type = payload.pop("type", None)
        row: dict[str, Any] = {"time": _utc_now(), "event_kind": kind, **payload}
        if resource_type is not None:
            row["resource_type"] = resource_type
        _append_jsonl(self.events_path, row)

    def _request(self, event: dict[str, Any]) -> None:
        self.request_event_count += 1
        request_id = str(event.get("requestId") or "")
        self.requests[request_id] = event
        url = str((event.get("request") or {}).get("url") or "")
        lowered = url.lower()
        if any(marker in lowered for marker in ("authchallenge", "hcaptchapassive", "/captcha/", "datadome")):
            self.challenge_urls.append(url)
        self._record("requestWillBeSent", event)

    def _request_extra(self, event: dict[str, Any]) -> None:
        request_id = str(event.get("requestId") or "")
        self.extra_headers[request_id] = dict(event.get("headers") or {})
        self._record("requestWillBeSentExtraInfo", event)

    def _response(self, event: dict[str, Any]) -> None:
        self.response_event_count += 1
        request_id = str(event.get("requestId") or "")
        self.responses[request_id] = event
        response = dict(event.get("response") or {})
        url = str(response.get("url") or "")
        protocol = str(response.get("protocol") or "unknown")
        if urllib.parse.urlsplit(url).scheme.lower() == "https":
            self.https_protocol_counts[protocol] = self.https_protocol_counts.get(protocol, 0) + 1
        if str(event.get("type") or "") == "Document":
            self.main_documents.append(
                {
                    "path": urllib.parse.urlsplit(url).path or "/",
                    "status": int(response.get("status") or 0),
                    "protocol": protocol,
                    "mime_type": str(response.get("mimeType") or ""),
                }
            )
        self._record("responseReceived", event)

    def _response_extra(self, event: dict[str, Any]) -> None:
        self._record("responseReceivedExtraInfo", event)

    def _loading_failed(self, event: dict[str, Any]) -> None:
        self.loading_failed_count += 1
        self._record("loadingFailed", event)

    def transport_summary(self) -> dict[str, Any]:
        return {
            "request_events": self.request_event_count,
            "response_events": self.response_event_count,
            "request_response_delta": self.request_event_count - self.response_event_count,
            "loading_failed_events": self.loading_failed_count,
            "https_protocol_counts": dict(sorted(self.https_protocol_counts.items())),
            "main_documents": list(self.main_documents),
        }

    def _finished(self, event: dict[str, Any]) -> None:
        self._record("loadingFinished", event)
        request_id = str(event.get("requestId") or "")
        response = self.responses.get(request_id) or {}
        mime = str((response.get("response") or {}).get("mimeType") or "")
        if not (mime.startswith("text/") or any(x in mime for x in ("json", "javascript", "xml"))):
            return
        try:
            body = self.cdp.send("Network.getResponseBody", {"requestId": request_id})
            data = body.get("body") or ""
            suffix = ".b64" if body.get("base64Encoded") else ".txt"
            path = self.bodies_dir / f"{_safe_filename(request_id)}{suffix}"
            path.write_text(str(data), encoding="utf-8")
        except Exception as exc:
            self._record("responseBodyError", {"requestId": request_id, "error": str(exc)})

    def _paused(self, event: dict[str, Any]) -> None:
        request = event.get("request") or {}
        if "/checkoutweb/signup" in str(request.get("url") or "") and self.paused_signup is None:
            self.paused_signup = event
            self._record("signupRequestPaused", event)
            return
        self.cdp.send("Fetch.continueRequest", {"requestId": event["requestId"]})

    def fail_paused_signup(self) -> None:
        if not self.paused_signup:
            return
        try:
            self.cdp.send("Fetch.failRequest", {"requestId": self.paused_signup["requestId"], "errorReason": "Aborted"})
        except Exception:
            pass


class RoxySignupLab:
    def __init__(
        self,
        *,
        mode: str,
        ba_token: str,
        phone: str,
        proxy_line: str,
        capture_root: str | Path,
        protocol_transport: str = "httpx",
        keep_profile: bool = False,
    ):
        if mode not in {"reference", "handoff"}:
            raise ValueError(f"unsupported Roxy signup lab mode: {mode}")
        self.mode = mode
        self.ba_token = parse_ba_token(ba_token)
        self.phone = phone
        self.country_profile = profile_for_phone(phone)
        self.proxy_entry = ProxyEntry.parse(proxy_line)
        self.capture_root = Path(capture_root).expanduser().resolve()
        self.protocol_transport = protocol_transport
        self.keep_profile = keep_profile

    def _click_first(self, page: Any, labels: tuple[str, ...]) -> bool:
        for label in labels:
            candidates = (
                page.get_by_role("button", name=re.compile(label, re.I)),
                page.get_by_role("link", name=re.compile(label, re.I)),
                page.get_by_text(re.compile(label, re.I), exact=False),
            )
            for locator in candidates:
                try:
                    if locator.count() and locator.first.is_visible():
                        locator.first.click(timeout=5000)
                        return True
                except Exception:
                    continue
        return False

    @staticmethod
    def _page_stage(url: str) -> str:
        path = urllib.parse.urlsplit(url).path.lower()
        if path.startswith("/checkoutweb/signup"):
            return "checkoutweb_signup"
        if path.startswith("/pay/checkout/signup/contact"):
            return "contact"
        if path == "/pay" or path.startswith("/pay/"):
            return "pay"
        if path.startswith("/agreements/approve"):
            return "approval"
        return "unknown"

    def _capture_controls(self, page: Any, context: BrowserSignupContext, stage: str) -> None:
        try:
            controls = page.locator("input, select, textarea, button, a").evaluate_all(
                """elements => elements.slice(0, 100).map((el, index) => ({
                    index, tag: el.tagName.toLowerCase(), type: el.type || '',
                    name: el.name || '', id: el.id || '', autocomplete: el.autocomplete || '',
                    placeholder: el.placeholder || '', ariaLabel: el.getAttribute('aria-label') || '',
                    text: (el.innerText || el.value || '').trim().slice(0, 120),
                    visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                }))"""
            )
        except Exception as exc:
            controls = [{"capture_error": str(exc)}]
        _append_jsonl(
            self.capture_root / "browser" / "control-summaries.jsonl",
            {"time": _utc_now(), "stage": stage, "url_path": urllib.parse.urlsplit(page.url).path, "controls": controls},
        )
        context.stages.append({"time": _utc_now(), "event": "controls_captured", "stage": stage})

    def _challenge_evidence(self, page: Any, capture: CdpCapture, body: str) -> tuple[list[str], list[str]]:
        terminal = [marker for marker in _CHALLENGE_MARKERS if marker in body.lower()]
        observed: list[str] = []
        url_lower = page.url.lower()
        if any(marker in url_lower for marker in ("authchallenge", "/captcha/", "datadome")):
            terminal.append("challenge_url")
        try:
            cookies = page.context.cookies()
        except Exception:
            cookies = []
        tsrce = next((str(item.get("value") or "").lower() for item in cookies if item.get("name") == "tsrce"), "")
        if "authchallenge" in tsrce:
            observed.append("tsrce_authchallenge")
        if capture.challenge_urls:
            observed.append("passive_challenge_network")
        return list(dict.fromkeys(terminal)), list(dict.fromkeys(observed))

    @staticmethod
    def _stop_before_contact_submission(context: BrowserSignupContext) -> None:
        context.ui_generation = "contact_signup"
        context.stages.append(
            {
                "time": _utc_now(),
                "event": "contact_signup_stopped",
                "reason": "phone_submission_out_of_scope",
            }
        )
        raise RuntimeError("ROXY_CONTACT_SIGNUP_STOPPED")

    def _drive_to_signup(self, page: Any, capture: CdpCapture, context: BrowserSignupContext) -> None:
        deadline = time.monotonic() + 150
        last_url = ""
        captured_stages: set[str] = set()
        completed_actions: set[str] = set()
        stage_entered_at: dict[str, float] = {}
        last_observed_challenge: tuple[str, ...] = ()
        pay_create_account_selected = False
        pay_form_submitted = False
        while time.monotonic() < deadline:
            page.wait_for_timeout(350)
            url = page.url
            if url != last_url:
                context.stages.append({"time": _utc_now(), "event": "url", "url": url})
                last_url = url
            if capture.paused_signup is not None:
                return
            if "/checkoutweb/signup" in url:
                context.ui_generation = "legacy_checkoutweb"
                return
            if "/checkoutweb/genericError" in url:
                raise RuntimeError("ROXY_APPROVAL_NAVIGATION_FAILED")
            body = ""
            try:
                body = page.locator("body").inner_text(timeout=1500)[:10000]
            except Exception:
                pass
            markers, observed = self._challenge_evidence(page, capture, body)
            observed_key = tuple(observed)
            if observed and observed_key != last_observed_challenge:
                context.stages.append({"time": _utc_now(), "event": "passive_challenge_observed", "markers": observed})
            last_observed_challenge = observed_key
            if markers:
                context.challenge_markers = list(dict.fromkeys(observed + markers))
                raise RuntimeError("ROXY_SIGNUP_CHALLENGED")
            stage = self._page_stage(url)
            context.ui_generation = classify_signup_ui(url)
            stage_entered_at.setdefault(stage, time.monotonic())
            if stage not in captured_stages:
                self._capture_controls(page, context, stage)
                captured_stages.add(stage)
            if stage == "approval" and "approval_continue" not in completed_actions:
                email_filled = False
                for selector in ("input[type=email]", "input[name=login_email]", "input[name=email]"):
                    locator = page.locator(selector)
                    try:
                        if locator.count() and locator.first.is_visible():
                            # The lab only needs a syntactically valid email to reach signup.
                            email = f"signup-lab-{int(time.time())}@example.com"
                            locator.first.fill(email)
                            email_filled = True
                            context.stages.append({"time": _utc_now(), "event": "email_filled"})
                            break
                    except Exception:
                        continue
                if email_filled and self._click_first(page, (r"continue", r"next")):
                    completed_actions.add("approval_continue")
                    context.stages.append({"time": _utc_now(), "event": "approval_continue"})
                    continue
            elif stage == "pay" and not pay_form_submitted:
                # The login and create-account views share /pay. Switch the
                # DOM view once, then submit the app-owned email form once.
                if time.monotonic() - stage_entered_at[stage] < 4.0:
                    continue
                form = page.locator('form[data-testid="emailForm"]')
                if not form.count() and not pay_create_account_selected:
                    if self._click_first(page, (r"create an account", r"create account")):
                        pay_create_account_selected = True
                        context.stages.append({"time": _utc_now(), "event": "pay_create_account_view_selected"})
                        continue
                email_input = form.locator('input[name="login_email"]')
                continue_button = form.locator('button[data-testid="continueButton"]')
                try:
                    if form.count() and email_input.count() and continue_button.count():
                        email = f"signup-lab-{int(time.time())}@example.com"
                        email_input.first.fill(email)
                        continue_button.first.click(timeout=5000)
                        pay_form_submitted = True
                        context.stages.append({"time": _utc_now(), "event": "pay_email_form_submitted"})
                        continue
                except Exception as exc:
                    context.stages.append({"time": _utc_now(), "event": "pay_email_form_error", "error_type": type(exc).__name__})
                if pay_create_account_selected and time.monotonic() - stage_entered_at[stage] > 20.0:
                    self._capture_controls(page, context, "pay_email_form_missing")
                    raise RuntimeError("ROXY_CREATE_ACCOUNT_CONTROL_MISSING")
            elif stage == "contact":
                self._stop_before_contact_submission(context)
        raise RuntimeError("ROXY_SIGNUP_REDIRECT_TIMEOUT")

    def _capture_failure_page(self, page: Any, context: BrowserSignupContext) -> None:
        try:
            failure_dir = self.capture_root / "browser"
            (failure_dir / "failure.html").write_text(page.content(), encoding="utf-8")
            page.screenshot(path=str(failure_dir / "failure.png"), full_page=True)
            context.final_url = page.url
        except Exception as exc:
            context.classification["failure_capture_error"] = str(exc)

    @staticmethod
    def _extract_context(url: str, html: str) -> tuple[str, str, str]:
        material = f"{url}\n{html}"
        ec = re.search(r"\bEC-[A-Za-z0-9]+\b", material)
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        return (
            (query.get("token") or [ec.group(0) if ec else ""])[0],
            (query.get("ssrt") or [""])[0],
            (query.get("ctxId") or [""])[0],
        )

    def _protocol_handoff(self, paused: dict[str, Any], cookies: list[dict[str, Any]], output: Path) -> dict[str, Any]:
        request = dict(paused.get("request") or {})
        url = str(request.get("url") or "")
        headers = {str(k): str(v) for k, v in dict(request.get("headers") or {}).items()}
        headers.pop("Host", None)
        headers.pop("host", None)
        cookie_header = "; ".join(
            f"{item.get('name')}={item.get('value')}"
            for item in cookies
            if item.get("name") and item.get("value") is not None
        )
        if cookie_header:
            headers["Cookie"] = cookie_header
        output.mkdir(parents=True, exist_ok=True)
        _write_json(output / "request.json", {"method": "GET", "url": url, "headers": headers})
        if self.protocol_transport == "curl-chrome":
            try:
                from curl_cffi.requests import Session as CurlSession
            except ImportError as exc:
                raise RuntimeError("curl_cffi is required for curl-chrome transport") from exc
            client: Any = CurlSession(impersonate="chrome")
            client.proxies = {"http": self.proxy_entry.url, "https": self.proxy_entry.url}
            response = client.get(url, headers=headers, timeout=30, allow_redirects=False)
            body = response.text
            response_headers = dict(response.headers)
            client.close()
        else:
            with httpx.Client(proxy=self.proxy_entry.url, timeout=30, follow_redirects=False, http2=True, trust_env=False) as client:
                response = client.get(url, headers=headers)
                body = response.text
                response_headers = dict(response.headers)
        content_type = response_headers.get("content-type") or response_headers.get("Content-Type") or ""
        (output / "response.body").write_text(body, encoding="utf-8", errors="replace")
        classification = classify_signup_document(int(response.status_code), content_type, body, url)
        result = {
            "transport": self.protocol_transport,
            "url": url,
            "status": int(response.status_code),
            "headers": response_headers,
            "classification": classification,
        }
        _write_json(output / "result.json", result)
        return result

    def run(self) -> dict[str, Any]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("playwright is required for signup lab") from exc

        self.capture_root.mkdir(parents=True, exist_ok=True)
        profile = browser_profile_for(self.country_profile, BROWSER_PROFILE)
        config = load_roxy_capture_config(proxy_url=self.proxy_entry.url, browser_profile=profile)
        config.headless = False
        config.close_after_capture = False
        config.delete_after_capture = False
        if config.workspace_id is None or config.project_id is None:
            raise RoxyFingerprintError("signup lab requires fixed PAYPAL_ROXY_WORKSPACE_ID and PAYPAL_ROXY_PROJECT_ID")
        client = RoxyApiClient(config)
        context_result = BrowserSignupContext(workspace_id=config.workspace_id, project_id=config.project_id)
        context_result.browser_open_args = _roxy_open_args(config.proxy_url)
        context_result.http2_disabled_requested = "--disable-http2" in context_result.browser_open_args
        profile_id = ""
        succeeded = False
        browser = None
        capture: CdpCapture | None = None
        try:
            profile_id = client.create_profile(config.workspace_id, config.project_id)
            context_result.profile_id = profile_id
            _write_json(
                self.capture_root / "roxy_profile.json",
                {
                    "workspace_id": config.workspace_id,
                    "project_id": config.project_id,
                    "profile_id": profile_id,
                    "created_at": _utc_now(),
                    "cleanup_status": "pending",
                },
            )
            client.randomize_profile(config.workspace_id, profile_id)
            cdp_info = client.open_profile(config.workspace_id, profile_id)
            endpoint = _connect_over_cdp(cdp_info)
            with sync_playwright() as playwright:
                browser = playwright.chromium.connect_over_cdp(endpoint, timeout=int(config.timeout_seconds * 1000))
                contexts = browser.contexts
                if len(contexts) != 1:
                    raise RuntimeError(f"expected one Roxy context, got {len(contexts)}")
                browser_context = contexts[0]
                pages = browser_context.pages
                page = pages[0] if pages else browser_context.new_page()
                for stale in list(browser_context.pages):
                    if stale is not page:
                        stale.close()
                cdp = browser_context.new_cdp_session(page)
                capture = CdpCapture(cdp, self.capture_root / "browser", pause_signup=self.mode == "handoff")
                capture.start()
                approval_url = f"https://www.paypal.com/agreements/approve?ba_token={self.ba_token}"
                context_result.stages.append({"time": _utc_now(), "event": "approval_start"})
                page.goto(approval_url, wait_until="domcontentloaded", timeout=45000)
                try:
                    self._drive_to_signup(page, capture, context_result)
                except Exception:
                    self._capture_failure_page(page, context_result)
                    raise
                cookies = browser_context.cookies()
                context_result.cookies = cookies
                if self.mode == "handoff":
                    if not capture.paused_signup:
                        raise RuntimeError("ROXY_SIGNUP_REQUEST_NOT_PAUSED")
                    paused_request = capture.paused_signup.get("request") or {}
                    context_result.final_url = str(paused_request.get("url") or "")
                    context_result.request_headers = dict(paused_request.get("headers") or {})
                    html = page.content()
                    context_result.ec_token, context_result.ssrt, context_result.ctx_id = self._extract_context(context_result.final_url, html)
                    protocol = self._protocol_handoff(capture.paused_signup, cookies, self.capture_root / "protocol")
                    context_result.http_status = int(protocol.get("status") or 0)
                    context_result.content_type = str((protocol.get("classification") or {}).get("content_type") or "")
                    context_result.classification = dict(protocol.get("classification") or {})
                    context_result.status = "protocol_signup_ready" if context_result.classification.get("valid") else "signup_blocked"
                    capture.fail_paused_signup()
                else:
                    page.wait_for_timeout(1200)
                    context_result.final_url = page.url
                    html = page.content()
                    response_rec = next(
                        (item for item in reversed(list(capture.responses.values())) if "/checkoutweb/signup" in str((item.get("response") or {}).get("url") or "")),
                        {},
                    )
                    response_data = response_rec.get("response") or {}
                    context_result.http_status = int(response_data.get("status") or 0)
                    context_result.content_type = str(response_data.get("mimeType") or "")
                    context_result.ec_token, context_result.ssrt, context_result.ctx_id = self._extract_context(page.url, html)
                    context_result.classification = classify_signup_document(context_result.http_status, context_result.content_type, html, page.url)
                    context_result.status = "browser_signup_ready" if context_result.classification.get("valid") else "signup_blocked"
                    (self.capture_root / "browser" / "final.html").write_text(html, encoding="utf-8")
                    page.screenshot(path=str(self.capture_root / "browser" / "final.png"), full_page=True)
                context_result.same_context_page = len(browser_context.pages) == 1 and browser_context.pages[0] is page
                succeeded = bool(context_result.classification.get("valid"))
                browser.close()
                browser = None
        except Exception as exc:
            context_result.status = "failed"
            context_result.classification = {**context_result.classification, "error": str(exc)}
            logger.error("Signup lab failed: {}", exc)
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            should_delete = bool(profile_id and succeeded and not self.keep_profile)
            if should_delete:
                try:
                    client.close_profile(profile_id)
                except Exception:
                    pass
                try:
                    client.delete_profile(config.workspace_id, profile_id)
                    _write_json(
                        self.capture_root / "roxy_profile.json",
                        {
                            "workspace_id": config.workspace_id,
                            "project_id": config.project_id,
                            "profile_id": profile_id,
                            "cleanup_status": "deleted",
                            "cleaned_at": _utc_now(),
                        },
                    )
                except Exception as exc:
                    context_result.profile_retained = True
                    context_result.classification["cleanup_error"] = str(exc)
            elif profile_id:
                context_result.profile_retained = True
            client.close()

        if capture is not None:
            context_result.transport_summary = capture.transport_summary()
        context_result.stage_timing = _stage_timing_summary(context_result.stages)

        raw = asdict(context_result)
        _write_json(self.capture_root / "browser_signup_context.json", raw)
        safe = {
            "status": context_result.status,
            "ba_hash": _hash(self.ba_token),
            "proxy_hash": _hash(self.proxy_entry.url),
            "country": self.country_profile.country,
            "ui_generation": context_result.ui_generation,
            "http_status": context_result.http_status,
            "classification": context_result.classification,
            "browser_transport": {
                "open_args": context_result.browser_open_args,
                "http2_disabled_requested": context_result.http2_disabled_requested,
                **context_result.transport_summary,
            },
            "stage_timing": context_result.stage_timing,
            "profile_retained": context_result.profile_retained,
            "capture_root": str(self.capture_root),
        }
        _write_json(self.capture_root / "checkpoint.json", safe)
        return safe


def default_capture_root(mode: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path.cwd() / "captures" / "signup-lab" / f"{stamp}-{mode}"


def run_signup_lab_from_file(
    *,
    mode: str,
    input_file: str | Path,
    capture_dir: str | Path | None = None,
    protocol_transport: str = "httpx",
    keep_profile: bool = False,
) -> dict[str, Any]:
    inputs = SignupLabInputs.load(input_file)
    ba_token, proxy = inputs.selection()
    root = Path(capture_dir).expanduser().resolve() if capture_dir else default_capture_root(mode).resolve()
    logger.info(
        "Signup lab start mode={} country={} ba_hash={} proxy_hash={} capture={}",
        mode,
        profile_for_phone(inputs.phone).country,
        _hash(ba_token),
        _hash(ProxyEntry.parse(proxy).url),
        root,
    )
    if mode == "cold-protocol":
        return run_cold_protocol_signup(
            ba_token=ba_token,
            phone=inputs.phone,
            proxy_line=proxy,
            capture_root=root,
            protocol_transport=protocol_transport,
        )
    return RoxySignupLab(
        mode=mode,
        ba_token=ba_token,
        phone=inputs.phone,
        proxy_line=proxy,
        capture_root=root,
        protocol_transport=protocol_transport,
        keep_profile=keep_profile,
    ).run()


def run_cold_protocol_signup(
    *,
    ba_token: str,
    phone: str,
    proxy_line: str,
    capture_root: str | Path,
    protocol_transport: str = "httpx",
) -> dict[str, Any]:
    """Run protocol Phase 0/2 only, with no Roxy API construction or call."""
    from paypal.flow import PayPalFlow
    from paypal.models import generate_address, generate_card, generate_user
    from paypal.proxy import ProxyConfig
    from tools.compare_paypal_traffic import compare, write_markdown

    root = Path(capture_root).expanduser().resolve()
    profile = profile_for_phone(phone)
    proxy = ProxyEntry.parse(proxy_line)
    recorder = TrafficRecorder(root / "protocol", lab_raw=True)
    set_current_traffic_recorder(recorder)
    try:
        flow = PayPalFlow(
            ba_token=ba_token,
            user=generate_user(phone, profile),
            card=generate_card(proxy_url=proxy.url),
            address=generate_address(profile),
            proxy_config=ProxyConfig(enabled=True, entry=proxy),
            fingerprint_source="random",
            datadome_mode="protocol",
            mtr_runtime="python_generated",
            risk_signals_mode="protocol",
            country_profile=profile,
            protocol_transport=protocol_transport,
        )
        result = flow.run_until_signup()
    finally:
        recorder.close()
        clear_current_traffic_recorder()
    result.update(
        {
            "ba_hash": _hash(ba_token),
            "proxy_hash": _hash(proxy.url),
            "country": profile.country,
            "capture_root": str(root),
        }
    )
    _write_json(root / "protocol_result.json", result)
    browser_root = root / "browser"
    if (browser_root / "network" / "events.jsonl").exists():
        report = compare(root / "protocol", browser_root)
        _write_json(root / "diff" / "traffic_diff_report.json", report)
        write_markdown(report, root / "diff" / "traffic_diff_report.md")
    _write_json(
        root / "checkpoint.json",
        {
            "status": result.get("status"),
            "ba_hash": result["ba_hash"],
            "proxy_hash": result["proxy_hash"],
            "country": result["country"],
            "http_status": result.get("http_status"),
            "classification": result.get("classification"),
            "roxy_api_calls": 0,
            "capture_root": str(root),
        },
    )
    return result
