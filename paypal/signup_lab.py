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
import queue
import re
import threading
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
    _roxy_profile_startup_args,
    inspect_roxy_runtime_identity,
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
_SIGNUP_LAB_ROXY_API_TIMEOUT_SECONDS = 60.0
_SIGNUP_LAB_INPUT_LOCK = threading.Lock()
_EXISTING_PROFILE_CLEAR_ORIGINS = (
    "https://www.paypal.com",
    "https://paypal.com",
    "https://www.paypalobjects.com",
    "https://paypalobjects.com",
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


def audit_jsonl_capture(path: Path, *, expected_records: int) -> dict[str, Any]:
    """Validate that a capture contains one complete JSON object per line."""
    physical_lines = 0
    valid_json_lines = 0
    invalid_line_numbers: list[int] = []
    sequence: list[int] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, raw in enumerate(handle, start=1):
                physical_lines += 1
                try:
                    row = json.loads(raw)
                except (TypeError, ValueError, json.JSONDecodeError):
                    invalid_line_numbers.append(line_number)
                    continue
                if not isinstance(row, dict):
                    invalid_line_numbers.append(line_number)
                    continue
                valid_json_lines += 1
                try:
                    sequence.append(int(row.get("seq")))
                except (TypeError, ValueError):
                    sequence.append(-1)
    except OSError as exc:
        return {
            "valid": False,
            "expected_records": expected_records,
            "physical_lines": physical_lines,
            "valid_json_lines": valid_json_lines,
            "invalid_json_lines": max(1, len(invalid_line_numbers)),
            "invalid_line_numbers": invalid_line_numbers[:20],
            "sequence_contiguous": False,
            "error_type": type(exc).__name__,
        }

    sequence_contiguous = sequence == list(range(1, expected_records + 1))
    valid = (
        not invalid_line_numbers
        and physical_lines == expected_records
        and valid_json_lines == expected_records
        and sequence_contiguous
    )
    return {
        "valid": valid,
        "expected_records": expected_records,
        "physical_lines": physical_lines,
        "valid_json_lines": valid_json_lines,
        "invalid_json_lines": len(invalid_line_numbers),
        "invalid_line_numbers": invalid_line_numbers[:20],
        "sequence_contiguous": sequence_contiguous,
    }


class JsonlCaptureWriter:
    """Serialize CDP callbacks through one writer and audit the result."""

    _STOP = object()

    def __init__(self, path: Path):
        self.path = path
        self._queue: queue.Queue[object] = queue.Queue()
        self._state_lock = threading.Lock()
        self._sequence = 0
        self._closed = False
        self._writer_error_type = ""
        self._audit: dict[str, Any] | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(
            target=self._run,
            name="signup-lab-cdp-writer",
            daemon=True,
        )
        self._thread.start()

    def append(self, value: Mapping[str, Any]) -> None:
        with self._state_lock:
            if self._closed:
                raise RuntimeError("CDP capture writer is closed")
            self._sequence += 1
            sequence = self._sequence
        self._queue.put({"seq": sequence, **dict(value)})

    def _run(self) -> None:
        try:
            with self.path.open("w", encoding="utf-8", newline="\n") as handle:
                while True:
                    item = self._queue.get()
                    try:
                        if item is self._STOP:
                            return
                        handle.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
                        handle.flush()
                    finally:
                        self._queue.task_done()
        except Exception as exc:
            self._writer_error_type = type(exc).__name__

    def close(self, *, timeout_seconds: float = 15.0) -> dict[str, Any]:
        with self._state_lock:
            if self._audit is not None:
                return dict(self._audit)
            if not self._closed:
                self._closed = True
                self._queue.put(self._STOP)
            expected_records = self._sequence
        self._thread.join(timeout=max(0.1, timeout_seconds))
        audit = audit_jsonl_capture(self.path, expected_records=expected_records)
        if self._thread.is_alive():
            audit.update({"valid": False, "error_type": "WRITER_DRAIN_TIMEOUT"})
        elif self._writer_error_type:
            audit.update({"valid": False, "error_type": self._writer_error_type})
        with self._state_lock:
            self._audit = dict(audit)
        return audit


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
    path = urllib.parse.urlsplit(url or "").path.lower().rstrip("/") or "/"
    signup_shape = any(
        marker in lowered
        for marker in ("__initial_data__", "checkoutweb", "weasley", "signup")
    )
    challenge_path = any(
        marker in path
        for marker in ("authchallenge", "/captcha", "datadome", "/interstitial")
    )
    terminal_challenge = bool(challenge) and (
        int(status or 0) >= 400 or challenge_path or not signup_shape
    )
    passive_challenge = challenge if challenge and not terminal_challenge else []
    valid = (
        status == 200
        and "text/html" in (content_type or "").lower()
        and path == "/checkoutweb/signup"
        and signup_shape
        and not terminal_challenge
        and not invalid_ba
    )
    return {
        "valid": valid,
        "status": status,
        "content_type": content_type,
        "bytes": len((body or "").encode("utf-8", errors="replace")),
        "body_sha256": hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest(),
        "challenge_markers": challenge,
        "terminal_challenge_markers": challenge if terminal_challenge else [],
        "passive_challenge_markers": passive_challenge,
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
    failed_proxy_hashes: set[str] = field(default_factory=set)

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
        failed_proxy_hashes = {
            str(value).strip().lower()
            for value in data.get("failed_proxy_hashes", [])
            if str(value).strip()
        }
        return cls(
            ba_tokens=tokens,
            phone=phone,
            proxies=proxies,
            next_ba_index=int(data.get("next_ba_index") or 0) % len(tokens),
            next_proxy_index=int(data.get("next_proxy_index") or 0) % len(proxies),
            failed_proxy_hashes=failed_proxy_hashes,
        )

    def selected_proxy_index(self) -> int:
        for offset in range(len(self.proxies)):
            index = (self.next_proxy_index + offset) % len(self.proxies)
            proxy_hash = _hash(ProxyEntry.parse(self.proxies[index]).url)
            if proxy_hash not in self.failed_proxy_hashes:
                return index
        raise ValueError("signup lab proxy pool has no non-quarantined SID")

    def selection(self) -> tuple[str, str]:
        proxy_index = self.selected_proxy_index()
        return (
            self.ba_tokens[self.next_ba_index % len(self.ba_tokens)],
            self.proxies[proxy_index],
        )

    @staticmethod
    def _write_state(source: Path, data: Mapping[str, Any]) -> None:
        temporary = source.with_name(
            f".{source.name}.{os.getpid()}.{time.time_ns()}.tmp"
        )
        try:
            temporary.write_text(
                json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, source)
        finally:
            if temporary.exists():
                temporary.unlink()

    @classmethod
    def reserve_for_profile(
        cls,
        path: str | Path,
    ) -> tuple["SignupLabInputs", str, str, dict[str, Any]]:
        source = Path(path).expanduser().resolve()
        with _SIGNUP_LAB_INPUT_LOCK:
            inputs = cls.load(source)
            proxy_index = inputs.selected_proxy_index()
            ba_token = inputs.ba_tokens[inputs.next_ba_index % len(inputs.ba_tokens)]
            proxy_line = inputs.proxies[proxy_index]
            next_proxy_index = (proxy_index + 1) % len(inputs.proxies)
            data = json.loads(source.read_text(encoding="utf-8-sig"))
            data["next_proxy_index"] = next_proxy_index
            cls._write_state(source, data)
        return inputs, ba_token, proxy_line, {
            "selected_proxy_index": proxy_index,
            "next_proxy_index": next_proxy_index,
            "proxy_hash": _hash(ProxyEntry.parse(proxy_line).url),
            "quarantined_proxy_count": len(inputs.failed_proxy_hashes),
        }

    @classmethod
    def quarantine_proxy(cls, path: str | Path, proxy_line: str) -> tuple[str, bool]:
        source = Path(path).expanduser().resolve()
        proxy_hash = _hash(ProxyEntry.parse(proxy_line).url)
        with _SIGNUP_LAB_INPUT_LOCK:
            data = json.loads(source.read_text(encoding="utf-8-sig"))
            failed = {
                str(value).strip().lower()
                for value in data.get("failed_proxy_hashes", [])
                if str(value).strip()
            }
            added = proxy_hash not in failed
            failed.add(proxy_hash)
            data["failed_proxy_hashes"] = sorted(failed)
            cls._write_state(source, data)
        return proxy_hash, added


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
    profile_source: str = "created"
    profile_detail: dict[str, Any] = field(default_factory=dict)
    state_reset: dict[str, Any] = field(default_factory=dict)
    profile_cleanup: str = "pending"
    profile_retained: bool = False
    same_context_page: bool = True
    browser_create_args: list[str] = field(default_factory=list)
    browser_open_args: list[str] = field(default_factory=list)
    browser_open_mode: str = ""
    page_lifecycle: dict[str, Any] = field(default_factory=dict)
    http2_disabled_requested: bool = False
    transport_summary: dict[str, Any] = field(default_factory=dict)
    capture_integrity: dict[str, Any] = field(default_factory=dict)
    stage_timing: dict[str, Any] = field(default_factory=dict)
    ui_generation: str = "unknown"
    fingerprint_policy: dict[str, Any] = field(default_factory=dict)
    profile_freeze: dict[str, Any] = field(default_factory=dict)
    runtime_fingerprint: dict[str, Any] = field(default_factory=dict)
    warmup: dict[str, Any] = field(default_factory=dict)
    browser_force_open_requested: bool = False
    window_hold_seconds: float = 0.0
    window_hold_completed: bool = False
    manual_navigation: bool = False


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


def _configure_roxy_for_signup_lab(config: Any) -> None:
    config.headless = False
    config.force_open = True
    config.close_after_capture = False
    config.delete_after_capture = False
    config.timeout_seconds = max(
        float(config.timeout_seconds),
        _SIGNUP_LAB_ROXY_API_TIMEOUT_SECONDS,
    )


def _configure_roxy_for_randomized_ios(config: Any) -> None:
    """Use the approval-control fingerprint lifecycle for new lab Profiles."""
    config.core_type = "Chrome"
    config.core_version = "136"
    config.os_name = "IOS"
    config.os_version = "18"
    config.web_rtc_mode = 0
    config.headless = False
    # The successful control opens the persisted Profile without launch-time
    # mutation. Headed mode is already frozen into the Profile itself.
    config.force_open = False
    config.close_before_open = False
    config.close_after_capture = False
    config.delete_after_capture = False
    config.timeout_seconds = max(
        float(config.timeout_seconds),
        _SIGNUP_LAB_ROXY_API_TIMEOUT_SECONDS,
    )


def _randomized_ios_policy_summary(config: Any) -> dict[str, Any]:
    return {
        "name": "ios18-chrome136-randomized",
        "core_type": str(config.core_type),
        "core_version": str(config.core_version),
        "os_name": str(config.os_name),
        "os_version": str(config.os_version),
        "web_rtc_mode": int(config.web_rtc_mode),
        "headless": bool(config.headless),
        "random_fingerprint": True,
        "refresh_host_identity": True,
    }


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
        self._events_writer = JsonlCaptureWriter(self.events_path)
        self.capture_integrity: dict[str, Any] = {}

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
        self._events_writer.append(row)

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

    def close(self) -> dict[str, Any]:
        if not self.capture_integrity:
            self.capture_integrity = self._events_writer.close()
        return dict(self.capture_integrity)


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
        window_hold_seconds: float = 0.0,
        warmup: bool = False,
        existing_profile_id: str = "",
        existing_profile_name: str = "",
        manual_navigation: bool = False,
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
        self.window_hold_seconds = max(0.0, min(float(window_hold_seconds), 3600.0))
        self.warmup = bool(warmup)
        self.existing_profile_id = str(existing_profile_id or "").strip()
        self.existing_profile_name = str(existing_profile_name or "").strip()
        self.manual_navigation = bool(manual_navigation)
        if self.existing_profile_id and mode != "reference":
            raise ValueError("existing Roxy Profile is supported only in reference mode")
        if self.existing_profile_name and not self.existing_profile_id:
            raise ValueError("existing Roxy Profile name verification requires an explicit Profile ID")
        if self.existing_profile_id and self.warmup:
            raise ValueError("clean existing-Profile reference cannot also use warm-up state")
        if self.manual_navigation and not self.existing_profile_id:
            raise ValueError("manual navigation requires an explicit existing Roxy Profile")

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

    @staticmethod
    def _navigate_to_approval(
        page: Any,
        approval_url: str,
        context: BrowserSignupContext,
    ) -> Any:
        # Waiting for DOMContentLoaded can stall on a 403 document whose body
        # never finishes.  A committed navigation already exposes the main
        # response status and lets the lab terminate the challenged SID.
        response = page.goto(approval_url, wait_until="commit", timeout=45000)
        if int(getattr(response, "status", 0) or 0) == 403:
            context.challenge_markers = list(
                dict.fromkeys([*context.challenge_markers, "approval_http_403"])
            )
            raise RuntimeError("ROXY_SIGNUP_CHALLENGED")
        return response

    @staticmethod
    def _warm_up_same_page(page: Any, context: BrowserSignupContext) -> None:
        """Establish first-party state without probing or solving a challenge."""
        warmup_url = "https://www.paypal.com/"
        context.stages.append({"time": _utc_now(), "event": "warmup_start"})
        response = page.goto(warmup_url, wait_until="commit", timeout=45000)
        status = int(getattr(response, "status", 0) or 0)
        if status <= 0:
            raise RuntimeError("ROXY_WARMUP_NAVIGATION_FAILED")
        page.wait_for_timeout(5000)
        final_path = urllib.parse.urlsplit(str(page.url or warmup_url)).path or "/"
        cookies = page.context.cookies([warmup_url])
        cookie_names = sorted(
            {
                str(cookie.get("name") or "")
                for cookie in cookies
                if str(cookie.get("name") or "")
            }
        )
        context.warmup = {
            "enabled": True,
            "status": status,
            "final_path": final_path,
            "cookie_name_count": len(cookie_names),
            "cookie_names": cookie_names,
        }
        context.stages.append(
            {
                "time": _utc_now(),
                "event": "warmup_complete",
                "status": status,
                "path": final_path,
                "cookie_name_count": len(cookie_names),
            }
        )
        terminal_path = any(
            marker in final_path.lower()
            for marker in ("/captcha", "/interstitial", "/authchallenge")
        )
        if status >= 400 or terminal_path:
            context.challenge_markers = list(
                dict.fromkeys([*context.challenge_markers, "warmup_challenged"])
            )
            raise RuntimeError("ROXY_WARMUP_CHALLENGED")

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
        for document in getattr(capture, "main_documents", []):
            if not isinstance(document, Mapping):
                continue
            path = str(document.get("path") or "").lower().rstrip("/")
            status = int(document.get("status") or 0)
            if path == "/agreements/approve" and status == 403:
                terminal.append("approval_http_403")
            if path == "/captcha" or "authchallenge" in path or "datadome" in path:
                terminal.append("challenge_document")
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
            page.screenshot(
                path=str(failure_dir / "failure.png"),
                full_page=True,
                timeout=3000,
            )
            context.final_url = page.url
        except Exception as exc:
            context.classification["failure_capture_error"] = str(exc)

    def _hold_window(
        self,
        page: Any,
        context: BrowserSignupContext,
        *,
        reason: str,
    ) -> None:
        seconds = self.window_hold_seconds
        if seconds <= 0:
            return
        context.window_hold_seconds = seconds
        context.stages.append(
            {
                "time": _utc_now(),
                "event": "roxy_window_hold_start",
                "reason": reason,
                "seconds": seconds,
            }
        )
        logger.warning(
            "Roxy headed window hold start seconds={} reason={} profile_hash={}",
            seconds,
            reason,
            _hash(context.profile_id),
        )
        try:
            page.wait_for_timeout(int(seconds * 1000))
            context.window_hold_completed = True
        except Exception as exc:
            context.classification["window_hold_error_type"] = type(exc).__name__
        context.stages.append(
            {
                "time": _utc_now(),
                "event": "roxy_window_hold_end",
                "reason": reason,
                "seconds": seconds,
                "completed": context.window_hold_completed,
            }
        )
        logger.warning(
            "Roxy headed window hold end seconds={} reason={} completed={} profile_hash={}",
            seconds,
            reason,
            context.window_hold_completed,
            _hash(context.profile_id),
        )

    def _require_runtime_identity(
        self,
        page: Any,
        context: BrowserSignupContext,
    ) -> None:
        if context.runtime_fingerprint.get("verified"):
            return
        self._hold_window(page, context, reason="runtime_gate_failure")
        raise RuntimeError("ROXY_RUNTIME_FINGERPRINT_MISMATCH")

    def _wait_for_manual_approval(
        self,
        page: Any,
        capture: CdpCapture,
        context: BrowserSignupContext,
        *,
        timeout_seconds: float = 120.0,
    ) -> None:
        """Wait for an address-bar navigation already observed by CDP."""
        context.stages.append({"time": _utc_now(), "event": "manual_navigation_ready"})
        _write_json(
            self.capture_root / "manual_navigation_ready.json",
            {
                "ready": True,
                "profile_hash": _hash(context.profile_id),
                "page": "about:blank",
                "created_at": _utc_now(),
            },
        )
        logger.info(
            "Signup lab manual navigation ready profile_hash={} timeout_seconds={}",
            _hash(context.profile_id),
            timeout_seconds,
        )
        deadline = time.monotonic() + max(1.0, float(timeout_seconds))
        while time.monotonic() < deadline:
            approval_documents = [
                item
                for item in capture.main_documents
                if str(item.get("path") or "").rstrip("/") == "/agreements/approve"
            ]
            if approval_documents:
                document = approval_documents[-1]
                status = int(document.get("status") or 0)
                context.stages.append(
                    {
                        "time": _utc_now(),
                        "event": "manual_approval_observed",
                        "status": status,
                    }
                )
                if status >= 400:
                    context.challenge_markers = list(
                        dict.fromkeys([*context.challenge_markers, f"approval_http_{status}"])
                    )
                    raise RuntimeError("ROXY_SIGNUP_CHALLENGED")
                if 200 <= status < 400:
                    return
            page.wait_for_timeout(250)
        raise RuntimeError("ROXY_MANUAL_NAVIGATION_TIMEOUT")

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
        existing_control = bool(self.existing_profile_id)
        config = load_roxy_capture_config(
            proxy_url="" if existing_control else self.proxy_entry.url,
            browser_profile=profile,
        )
        if existing_control:
            _configure_roxy_for_signup_lab(config)
        else:
            _configure_roxy_for_randomized_ios(config)
        if config.workspace_id is None or config.project_id is None:
            raise RoxyFingerprintError("signup lab requires fixed PAYPAL_ROXY_WORKSPACE_ID and PAYPAL_ROXY_PROJECT_ID")
        client = RoxyApiClient(config)
        context_result = BrowserSignupContext(
            workspace_id=config.workspace_id,
            project_id=config.project_id,
            profile_source=(
                "existing_clean_control"
                if existing_control
                else "created_randomized_ios"
            ),
            fingerprint_policy=(
                {"source": "existing_profile_preserved"}
                if existing_control
                else _randomized_ios_policy_summary(config)
            ),
            browser_force_open_requested=(False if existing_control else bool(config.force_open)),
            window_hold_seconds=self.window_hold_seconds,
            manual_navigation=self.manual_navigation,
        )
        if not existing_control:
            context_result.browser_create_args = _roxy_profile_startup_args(
                config.proxy_url,
                open_width=config.open_width,
                open_height=config.open_height,
            )
            context_result.browser_open_mode = "preserve_randomized_profile_settings"
        else:
            context_result.browser_open_mode = "preserve_existing_profile_settings"
        context_result.http2_disabled_requested = any(
            value == "--disable-http2"
            for value in (
                *context_result.browser_create_args,
                *context_result.browser_open_args,
            )
        )
        profile_id = ""
        succeeded = False
        browser = None
        capture: CdpCapture | None = None
        try:
            if existing_control:
                profile_id = self.existing_profile_id
                detail = client.get_profile_detail(config.workspace_id, profile_id)
                if not detail:
                    raise RuntimeError("ROXY_EXISTING_PROFILE_DETAIL_MISSING")
                if self.existing_profile_name and str(detail.get("windowName") or "") != self.existing_profile_name:
                    raise RuntimeError("ROXY_EXISTING_PROFILE_NAME_MISMATCH")
                if not _profile_default_urls_are_blank(detail):
                    raise RuntimeError("ROXY_EXISTING_PROFILE_DEFAULT_URL_NOT_BLANK")
                context_result.profile_detail = _safe_existing_profile_detail(
                    detail,
                    expected_name=self.existing_profile_name,
                )
                _write_json(
                    self.capture_root / "browser" / "roxy_existing_profile_detail.json",
                    detail,
                )
                try:
                    client.close_profile(profile_id)
                    context_result.profile_cleanup = "closed_before_clean_control"
                except Exception as exc:
                    context_result.state_reset["preopen_close_error_type"] = type(exc).__name__
                cdp_info = client.open_existing_profile_preserving_settings(
                    config.workspace_id,
                    profile_id,
                )
            else:
                profile_id = client.create_profile(config.workspace_id, config.project_id)
            context_result.profile_id = profile_id
            _write_json(
                self.capture_root / "roxy_profile.json",
                {
                    "workspace_id": config.workspace_id,
                    "project_id": config.project_id,
                    "profile_id": profile_id,
                    "profile_source": context_result.profile_source,
                    "recorded_at": _utc_now(),
                    "cleanup_status": "pending",
                },
            )
            if not existing_control:
                profile_freeze = client.randomize_and_freeze_profile(
                    config.workspace_id,
                    profile_id,
                    preserve_randomized=True,
                    refresh_host_identity=True,
                )
                context_result.profile_freeze = dict(profile_freeze.get("verification") or {})
                _write_json(
                    self.capture_root / "browser" / "roxy_profile_detail.json",
                    {
                        "before": profile_freeze.get("before") or {},
                        "after": profile_freeze.get("after") or {},
                    },
                )
                if not context_result.profile_freeze.get("verified"):
                    raise RuntimeError("ROXY_PROFILE_POLICY_MISMATCH")
                cdp_info = client.open_existing_profile_preserving_settings(
                    config.workspace_id,
                    profile_id,
                )
            endpoint = _connect_over_cdp(cdp_info)
            with sync_playwright() as playwright:
                browser = playwright.chromium.connect_over_cdp(endpoint, timeout=int(config.timeout_seconds * 1000))
                contexts = browser.contexts
                if len(contexts) != 1:
                    raise RuntimeError(f"expected one Roxy context, got {len(contexts)}")
                browser_context = contexts[0]
                page, context_result.page_lifecycle = _create_dedicated_control_page(
                    browser_context
                )
                cdp = browser_context.new_cdp_session(page)
                if existing_control:
                    clear_existing_profile_state(
                        cdp,
                        browser_context,
                        page,
                        context_result,
                    )
                capture = CdpCapture(cdp, self.capture_root / "browser", pause_signup=self.mode == "handoff")
                capture.start()
                context_result.runtime_fingerprint = inspect_roxy_runtime_identity(
                    cdp,
                    page,
                    config,
                    preserve_randomized=not existing_control,
                )
                _write_json(
                    self.capture_root / "browser" / "runtime_fingerprint.json",
                    context_result.runtime_fingerprint,
                )
                if not existing_control:
                    self._require_runtime_identity(page, context_result)
                if self.warmup:
                    self._warm_up_same_page(page, context_result)
                approval_url = f"https://www.paypal.com/agreements/approve?ba_token={self.ba_token}"
                context_result.stages.append({"time": _utc_now(), "event": "approval_start"})
                try:
                    if self.manual_navigation:
                        self._wait_for_manual_approval(page, capture, context_result)
                    else:
                        self._navigate_to_approval(page, approval_url, context_result)
                    self._drive_to_signup(page, capture, context_result)
                except Exception:
                    self._capture_failure_page(page, context_result)
                    self._hold_window(page, context_result, reason="failure")
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
                self._hold_window(page, context_result, reason="result")
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
            if capture is not None:
                context_result.capture_integrity = capture.close()
                if not context_result.capture_integrity.get("valid"):
                    context_result.status = "failed"
                    context_result.classification = {
                        **context_result.classification,
                        "error": "CAPTURE_INTEGRITY_FAILED",
                    }
                    succeeded = False
            should_delete = bool(
                profile_id and succeeded and not self.keep_profile and not existing_control
            )
            if existing_control and profile_id:
                try:
                    client.close_profile(profile_id)
                    context_result.profile_cleanup = "closed_not_deleted"
                except Exception as exc:
                    context_result.profile_cleanup = "close_failed_not_deleted"
                    context_result.classification["cleanup_error_type"] = type(exc).__name__
                context_result.profile_retained = True
                _write_json(
                    self.capture_root / "roxy_profile.json",
                    {
                        "workspace_id": config.workspace_id,
                        "project_id": config.project_id,
                        "profile_id": profile_id,
                        "profile_source": context_result.profile_source,
                        "cleanup_status": context_result.profile_cleanup,
                        "cleaned_at": _utc_now(),
                    },
                )
            elif should_delete:
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
                    context_result.profile_cleanup = "deleted"
                except Exception as exc:
                    context_result.profile_retained = True
                    context_result.profile_cleanup = "delete_failed"
                    context_result.classification["cleanup_error"] = str(exc)
            elif profile_id:
                context_result.profile_retained = True
                context_result.profile_cleanup = "retained"
            client.close()

        if capture is not None:
            context_result.transport_summary = capture.transport_summary()
        context_result.stage_timing = _stage_timing_summary(context_result.stages)

        raw = asdict(context_result)
        _write_json(self.capture_root / "browser_signup_context.json", raw)
        safe = {
            "status": context_result.status,
            "ba_hash": _hash(self.ba_token),
            "proxy_hash": "" if existing_control else _hash(self.proxy_entry.url),
            "proxy_source": "existing_profile_preserved" if existing_control else "input_pool",
            "country": self.country_profile.country,
            "ui_generation": context_result.ui_generation,
            "profile_source": context_result.profile_source,
            "profile_hash": _hash(context_result.profile_id),
            "profile_detail": context_result.profile_detail,
            "profile_cleanup": context_result.profile_cleanup,
            "fingerprint_policy": context_result.fingerprint_policy,
            "profile_freeze": context_result.profile_freeze,
            "runtime_fingerprint": context_result.runtime_fingerprint,
            "state_reset": context_result.state_reset,
            "manual_navigation": context_result.manual_navigation,
            "warmup": context_result.warmup,
            "http_status": context_result.http_status,
            "classification": context_result.classification,
            "browser_transport": {
                "create_args": context_result.browser_create_args,
                "open_args": context_result.browser_open_args,
                "open_mode": context_result.browser_open_mode,
                "page_lifecycle": context_result.page_lifecycle,
                "http2_disabled_requested": context_result.http2_disabled_requested,
                **context_result.transport_summary,
            },
            "capture_integrity": context_result.capture_integrity,
            "stage_timing": context_result.stage_timing,
            "profile_retained": context_result.profile_retained,
            "window_lifecycle": {
                "headed": True,
                "force_open_requested": context_result.browser_force_open_requested,
                "hold_seconds": context_result.window_hold_seconds,
                "hold_completed": context_result.window_hold_completed,
            },
            "capture_root": str(self.capture_root),
        }
        _write_json(self.capture_root / "checkpoint.json", safe)
        return safe


class ApprovalCdpObserver:
    """Record only approval document evidence; never persist connection IP data."""

    def __init__(self, cdp: Any, root: Path):
        self.cdp = cdp
        self.writer = JsonlCaptureWriter(root / "approval-events.jsonl")
        self.main_documents: list[dict[str, Any]] = []

    @staticmethod
    def _url_shape(value: object) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(str(value or ""))
        return {
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "path": parsed.path or "/",
            "query_keys": sorted(urllib.parse.parse_qs(parsed.query, keep_blank_values=True)),
        }

    def _request(self, event: Mapping[str, Any]) -> None:
        if str(event.get("type") or "") != "Document":
            return
        request = event.get("request")
        request = dict(request) if isinstance(request, Mapping) else {}
        row = {
            "event_kind": "requestWillBeSent",
            "resource_type": "Document",
            "method": str(request.get("method") or ""),
            **self._url_shape(request.get("url")),
        }
        redirect = event.get("redirectResponse")
        if isinstance(redirect, Mapping):
            row["redirect_status"] = int(redirect.get("status") or 0)
            row["redirect_from"] = self._url_shape(redirect.get("url"))
        self.writer.append(row)

    def _response(self, event: Mapping[str, Any]) -> None:
        if str(event.get("type") or "") != "Document":
            return
        response = event.get("response")
        response = dict(response) if isinstance(response, Mapping) else {}
        document = {
            "event_kind": "responseReceived",
            "resource_type": "Document",
            "status": int(response.get("status") or 0),
            "mime_type": str(response.get("mimeType") or ""),
            "protocol": str(response.get("protocol") or ""),
            **self._url_shape(response.get("url")),
        }
        self.main_documents.append(dict(document))
        self.writer.append(document)

    def _failed(self, event: Mapping[str, Any]) -> None:
        if str(event.get("type") or "") != "Document":
            return
        self.writer.append(
            {
                "event_kind": "loadingFailed",
                "resource_type": "Document",
                "error_text": str(event.get("errorText") or ""),
                "canceled": bool(event.get("canceled")),
            }
        )

    def start(self) -> None:
        self.cdp.send("Page.enable")
        self.cdp.send("Network.enable")
        self.cdp.on("Network.requestWillBeSent", self._request)
        self.cdp.on("Network.responseReceived", self._response)
        self.cdp.on("Network.loadingFailed", self._failed)

    def close(self) -> dict[str, Any]:
        return self.writer.close()

    def summary(self) -> dict[str, Any]:
        return {"main_documents": list(self.main_documents)}


def _create_dedicated_control_page(browser_context: Any) -> tuple[Any, dict[str, Any]]:
    """Create the controlled Page before closing Roxy's transient startup Pages."""
    startup_pages = list(browser_context.pages)
    page = browser_context.new_page()
    closed = 0
    close_failures: list[str] = []
    for startup_page in startup_pages:
        if startup_page is page:
            continue
        try:
            startup_page.close()
            closed += 1
        except Exception as exc:
            close_failures.append(type(exc).__name__)
    return page, {
        "startup_page_count": len(startup_pages),
        "startup_pages_closed": closed,
        "startup_page_close_failures": close_failures,
        "dedicated_page_created": True,
    }


class RoxyApprovalControl:
    """Approval-only iOS Roxy control that never submits a page control."""

    def __init__(
        self,
        *,
        ba_token: str,
        phone: str,
        proxy_line: str,
        capture_root: str | Path,
        existing_profile_id: str = "",
        existing_profile_name: str = "",
    ):
        self.ba_token = parse_ba_token(ba_token)
        self.phone = str(phone or "").strip()
        self.country_profile = profile_for_phone(self.phone)
        self.proxy_entry = ProxyEntry.parse(proxy_line)
        self.capture_root = Path(capture_root).expanduser().resolve()
        self.existing_profile_id = str(existing_profile_id or "").strip()
        self.existing_profile_name = str(existing_profile_name or "").strip()
        if self.existing_profile_name and not self.existing_profile_id:
            raise ValueError("existing Profile name requires an explicit Profile ID")

    @staticmethod
    def _configure_ios_randomized(config: Any) -> None:
        _configure_roxy_for_randomized_ios(config)

    @staticmethod
    def _control_flags(page: Any) -> dict[str, bool]:
        def present(selector: str) -> bool:
            try:
                locator = page.locator(selector)
                return bool(locator.count() and locator.first.is_visible())
            except Exception:
                return False

        has_create_account = False
        try:
            locator = page.get_by_text(
                re.compile(r"create\s+(?:an\s+)?account", re.I),
                exact=False,
            )
            has_create_account = bool(locator.count() and locator.first.is_visible())
        except Exception:
            pass
        return {
            "has_email_control": present(
                'input[type="email"], input[autocomplete="email"], input[name*="email" i]'
            ),
            "has_create_account_control": has_create_account,
        }

    def run(self) -> dict[str, Any]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("playwright is required for approval control") from exc

        self.capture_root.mkdir(parents=True, exist_ok=True)
        profile = browser_profile_for(self.country_profile, BROWSER_PROFILE)
        config = load_roxy_capture_config(
            proxy_url=self.proxy_entry.url,
            browser_profile=profile,
        )
        self._configure_ios_randomized(config)
        if config.workspace_id is None or config.project_id is None:
            raise RoxyFingerprintError(
                "approval control requires fixed PAYPAL_ROXY_WORKSPACE_ID and PAYPAL_ROXY_PROJECT_ID"
            )
        client = RoxyApiClient(config)
        profile_id = self.existing_profile_id
        profile_source = "existing_randomized_control" if profile_id else "created_randomized_control"
        profile_freeze: dict[str, Any] = {}
        profile_detail: dict[str, Any] = {}
        runtime_fingerprint: dict[str, Any] = {}
        classification: dict[str, Any] = {"result": "approval_unknown", "valid": False}
        transport: dict[str, Any] = {"main_documents": []}
        capture_integrity: dict[str, Any] = {}
        profile_cleanup = "pending"
        observer: ApprovalCdpObserver | None = None
        browser = None
        http_status = 0
        final_path = ""
        error_type = ""
        failure_stage = "initialization"
        page_lifecycle: dict[str, Any] = {}
        try:
            failure_stage = "profile_selection"
            if profile_id:
                detail = client.get_profile_detail(config.workspace_id, profile_id)
                if not detail:
                    raise RuntimeError("ROXY_EXISTING_PROFILE_DETAIL_MISSING")
                if self.existing_profile_name and str(detail.get("windowName") or "") != self.existing_profile_name:
                    raise RuntimeError("ROXY_EXISTING_PROFILE_NAME_MISMATCH")
            else:
                profile_id = client.create_profile(config.workspace_id, config.project_id)
            _write_json(
                self.capture_root / "roxy_profile.json",
                {
                    "workspace_id": config.workspace_id,
                    "project_id": config.project_id,
                    "profile_id": profile_id,
                    "profile_source": profile_source,
                    "cleanup_status": "pending",
                },
            )
            try:
                client.close_profile(profile_id)
            except Exception:
                pass
            failure_stage = "profile_state_reset"
            client.clear_profile_cache(config.workspace_id, profile_id)
            failure_stage = "profile_randomize_and_freeze"
            frozen = client.randomize_and_freeze_profile(
                config.workspace_id,
                profile_id,
                preserve_randomized=True,
                refresh_host_identity=True,
            )
            profile_freeze = dict(frozen.get("verification") or {})
            if not profile_freeze.get("verified"):
                raise RuntimeError("ROXY_RANDOMIZED_PROFILE_POLICY_MISMATCH")
            detail = client.get_profile_detail(config.workspace_id, profile_id)
            profile_detail = _safe_existing_profile_detail(
                detail,
                expected_name=self.existing_profile_name,
            )
            failure_stage = "browser_open"
            cdp_info = client.open_existing_profile_preserving_settings(
                config.workspace_id,
                profile_id,
            )
            endpoint = _connect_over_cdp(cdp_info)
            with sync_playwright() as playwright:
                browser = playwright.chromium.connect_over_cdp(
                    endpoint,
                    timeout=int(config.timeout_seconds * 1000),
                )
                contexts = browser.contexts
                if len(contexts) != 1:
                    raise RuntimeError(f"expected one Roxy context, got {len(contexts)}")
                browser_context = contexts[0]
                failure_stage = "dedicated_page_create"
                page, page_lifecycle = _create_dedicated_control_page(browser_context)
                cdp = browser_context.new_cdp_session(page)
                observer = ApprovalCdpObserver(cdp, self.capture_root / "browser")
                observer.start()
                failure_stage = "runtime_fingerprint_verification"
                runtime_fingerprint = inspect_roxy_runtime_identity(
                    cdp,
                    page,
                    config,
                    preserve_randomized=True,
                )
                if not runtime_fingerprint.get("verified"):
                    raise RuntimeError("ROXY_RUNTIME_FINGERPRINT_MISMATCH")
                approval_url = (
                    "https://www.paypal.com/agreements/approve?ba_token="
                    f"{self.ba_token}"
                )
                failure_stage = "approval_navigation"
                response = page.goto(
                    approval_url,
                    wait_until="commit",
                    timeout=45000,
                )
                http_status = int(getattr(response, "status", 0) or 0)
                page.wait_for_timeout(6000)
                body = page.content()
                final_url = str(page.url or approval_url)
                final_path = urllib.parse.urlsplit(final_url).path or "/"
                headers = dict(getattr(response, "headers", {}) or {})
                content_type = str(
                    headers.get("content-type") or headers.get("Content-Type") or ""
                )
                flags = self._control_flags(page)
                failure_stage = "approval_classification"
                classification = classify_approval_document(
                    http_status,
                    content_type,
                    body,
                    final_url,
                    **flags,
                )
                (self.capture_root / "browser" / "final.html").write_text(
                    body,
                    encoding="utf-8",
                )
                try:
                    page.screenshot(
                        path=str(self.capture_root / "browser" / "final.png"),
                        full_page=True,
                        timeout=3000,
                    )
                except Exception:
                    pass
                if observer is not None:
                    transport = observer.summary()
                    capture_integrity = observer.close()
                    observer = None
                browser.close()
                browser = None
                failure_stage = "completed"
        except Exception as exc:
            error_type = type(exc).__name__
            logger.error(
                "Approval control failed error_type={} ba_hash={} proxy_hash={} profile_hash={}",
                error_type,
                _hash(self.ba_token),
                _hash(self.proxy_entry.url),
                _hash(profile_id),
            )
        finally:
            if observer is not None:
                try:
                    transport = observer.summary()
                    capture_integrity = observer.close()
                except Exception:
                    pass
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            if profile_id:
                try:
                    client.close_profile(profile_id)
                    profile_cleanup = "closed_retained"
                except Exception:
                    profile_cleanup = "close_failed_retained"
            client.close()

        if capture_integrity and not capture_integrity.get("valid"):
            classification = {
                **classification,
                "result": "approval_unknown",
                "valid": False,
                "capture_error": "CAPTURE_INTEGRITY_FAILED",
            }
        safe = {
            "status": classification.get("result") or "approval_unknown",
            "ba_hash": _hash(self.ba_token),
            "proxy_hash": _hash(self.proxy_entry.url),
            "country": self.country_profile.country,
            "profile_source": profile_source,
            "profile_hash": _hash(profile_id),
            "profile_detail": profile_detail,
            "profile_freeze": profile_freeze,
            "runtime_fingerprint": runtime_fingerprint,
            "http_status": http_status,
            "final_path": final_path,
            "classification": classification,
            "browser_transport": transport,
            "capture_integrity": capture_integrity,
            "profile_cleanup": profile_cleanup,
            "profile_retained": bool(profile_id),
            "error_type": error_type,
            "failure_stage": failure_stage,
            "page_lifecycle": page_lifecycle,
            "capture_root": str(self.capture_root),
        }
        _write_json(self.capture_root / "checkpoint.json", safe)
        return safe


def default_capture_root(mode: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path.cwd() / "captures" / "signup-lab" / f"{stamp}-{mode}"


def _approval_document_has_status(result: Mapping[str, Any], status: int) -> bool:
    transport = result.get("browser_transport")
    if not isinstance(transport, Mapping):
        return False
    documents = transport.get("main_documents")
    if not isinstance(documents, list):
        return False
    return any(
        isinstance(document, Mapping)
        and str(document.get("path") or "").rstrip("/") == "/agreements/approve"
        and int(document.get("status") or 0) == status
        for document in documents
    )


def _safe_existing_profile_detail(
    detail: Mapping[str, Any],
    *,
    expected_name: str = "",
) -> dict[str, Any]:
    """Return only non-secret fields needed for the control comparison."""
    user_agent = str(detail.get("userAgent") or detail.get("user_agent") or "")
    match = re.search(
        r"(?:Chrome|Chromium|RoxyChrome|CriOS)/(\d+)",
        user_agent,
        re.I,
    )
    default_urls = detail.get("defaultOpenUrl") or []
    if isinstance(default_urls, str):
        default_urls = [default_urls]
    proxy_info = detail.get("proxyInfo")
    proxy_info = dict(proxy_info) if isinstance(proxy_info, Mapping) else {}
    profile_name = str(detail.get("windowName") or "")
    return {
        "core_version": str(detail.get("coreVersion") or ""),
        "os": str(detail.get("os") or ""),
        "os_version": str(detail.get("osVersion") or ""),
        "user_agent_major": match.group(1) if match else "",
        "user_agent_hash": _hash(user_agent),
        "profile_name_hash": _hash(profile_name),
        "expected_name_verified": bool(expected_name and profile_name == expected_name),
        "default_open_url_count": len(default_urls),
        "finger_info_exposed": isinstance(detail.get("fingerInfo"), (dict, str)),
        "proxy_category": str(
            proxy_info.get("proxyCategory") or proxy_info.get("protocol") or "unknown"
        ),
        "proxy_authenticated": bool(
            proxy_info.get("proxyUserName") or proxy_info.get("proxyPassword")
        ),
    }


def classify_approval_document(
    status: int,
    content_type: str,
    body: str,
    url: str,
    *,
    has_email_control: bool = False,
    has_create_account_control: bool = False,
) -> dict[str, Any]:
    """Classify an approval-only result without submitting any page control."""
    lowered = (body or "").lower()
    path = urllib.parse.urlsplit(url or "").path.lower().rstrip("/") or "/"
    challenge = [marker for marker in _CHALLENGE_MARKERS if marker in lowered]
    if status == 403:
        challenge.append("approval_http_403")
    if any(marker in path for marker in ("authchallenge", "/captcha", "datadome")):
        challenge.append("challenge_url")
    invalid_ba = [marker for marker in _INVALID_BA_MARKERS if marker in lowered]
    ready_path = path == "/agreements/approve" or path == "/pay" or path.startswith("/pay/")
    ready_text = any(
        marker in lowered
        for marker in ("pay with paypal", "create an account", "create account")
    )
    ready_controls = bool(has_email_control or has_create_account_control)
    if challenge:
        result = "approval_challenged"
    elif invalid_ba:
        result = "approval_business_error"
    elif (
        200 <= int(status or 0) < 400
        and ready_path
        and (ready_text or ready_controls)
        and (not content_type or "html" in content_type.lower())
    ):
        result = "approval_ready"
    elif int(status or 0) <= 0:
        result = "approval_timeout"
    else:
        result = "approval_unknown"
    return {
        "result": result,
        "valid": result == "approval_ready",
        "status": int(status or 0),
        "content_type": content_type,
        "path": path,
        "bytes": len((body or "").encode("utf-8", errors="replace")),
        "body_sha256": hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest(),
        "challenge_markers": list(dict.fromkeys(challenge)),
        "invalid_ba_markers": invalid_ba,
        "ready_path": ready_path,
        "ready_text": ready_text,
        "has_email_control": bool(has_email_control),
        "has_create_account_control": bool(has_create_account_control),
    }


def _profile_default_urls_are_blank(detail: Mapping[str, Any]) -> bool:
    values = detail.get("defaultOpenUrl") or []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return False
    allowed = {"", "about:blank", "chrome://newtab/", "chrome://new-tab-page/"}
    return all(str(value or "").strip().lower() in allowed for value in values)


def clear_existing_profile_state(
    cdp: Any,
    browser_context: Any,
    page: Any,
    context: BrowserSignupContext,
) -> dict[str, Any]:
    """Clear all reusable browser state before the first target navigation."""
    context.stages.append({"time": _utc_now(), "event": "existing_profile_state_reset_start"})
    page.goto("about:blank", wait_until="commit", timeout=15000)

    failures: list[str] = []

    def send_required(method: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        try:
            value = cdp.send(method, dict(params or {}))
            return dict(value or {})
        except Exception as exc:
            failures.append(f"{method}:{type(exc).__name__}")
            return {}

    send_required("Network.enable")
    before = send_required("Network.getAllCookies").get("cookies") or []
    try:
        browser_context.clear_cookies()
    except Exception as exc:
        failures.append(f"BrowserContext.clear_cookies:{type(exc).__name__}")
    send_required("Network.clearBrowserCookies")
    send_required("Network.clearBrowserCache")
    for origin in _EXISTING_PROFILE_CLEAR_ORIGINS:
        send_required(
            "Storage.clearDataForOrigin",
            {"origin": origin, "storageTypes": "all"},
        )
        for is_local in (True, False):
            try:
                cdp.send(
                    "DOMStorage.clear",
                    {
                        "storageId": {
                            "securityOrigin": origin,
                            "isLocalStorage": is_local,
                        }
                    },
                )
            except Exception:
                # Storage.clearDataForOrigin is the required operation; this is
                # a compatibility fallback for Chromium builds that expose the
                # DOMStorage domain separately.
                pass
    try:
        cdp.send("ServiceWorker.enable")
        cdp.send("ServiceWorker.stopAllWorkers")
    except Exception:
        pass
    after = send_required("Network.getAllCookies").get("cookies") or []
    result = {
        "requested": True,
        "page_before_target": "about:blank",
        "cookies_before_count": len(before),
        "cookies_after_count": len(after),
        "http_cache_cleared": not any(
            item.startswith("Network.clearBrowserCache:") for item in failures
        ),
        "browser_cookies_cleared": not any(
            item.startswith(("Network.clearBrowserCookies:", "BrowserContext.clear_cookies:"))
            for item in failures
        ),
        "origins_cleared": len(_EXISTING_PROFILE_CLEAR_ORIGINS),
        "failures": failures,
        "verified": not failures and not after,
    }
    context.state_reset = result
    context.stages.append(
        {
            "time": _utc_now(),
            "event": "existing_profile_state_reset_complete",
            "verified": result["verified"],
            "cookies_before_count": len(before),
            "cookies_after_count": len(after),
        }
    )
    if not result["verified"]:
        raise RuntimeError("ROXY_EXISTING_PROFILE_STATE_RESET_FAILED")
    return result


def _persist_proxy_rotation(
    root: Path,
    result: dict[str, Any],
    rotation: Mapping[str, Any],
) -> None:
    safe_rotation = dict(rotation)
    result["proxy_rotation"] = safe_rotation
    _write_json(root / "proxy_rotation.json", safe_rotation)
    checkpoint = root / "checkpoint.json"
    if checkpoint.is_file():
        value = json.loads(checkpoint.read_text(encoding="utf-8-sig"))
        if isinstance(value, dict):
            value["proxy_rotation"] = safe_rotation
            _write_json(checkpoint, value)


def run_approval_control_from_file(
    *,
    input_file: str | Path,
    capture_dir: str | Path | None = None,
    rounds: int = 1,
    existing_profile_id: str = "",
    existing_profile_name: str = "",
) -> dict[str, Any]:
    """Run independent approval-only rounds with a fresh SID each time."""
    rounds = max(1, min(int(rounds), 10))
    root = (
        Path(capture_dir).expanduser().resolve()
        if capture_dir
        else default_capture_root("approval-control").resolve()
    )
    results: list[dict[str, Any]] = []
    for round_index in range(1, rounds + 1):
        inputs, ba_token, proxy, rotation = SignupLabInputs.reserve_for_profile(
            input_file
        )
        round_root = root / f"round-{round_index:02d}"
        logger.info(
            "Approval control round start round={}/{} ba_hash={} proxy_hash={} "
            "profile_source={} capture={}",
            round_index,
            rounds,
            _hash(ba_token),
            rotation["proxy_hash"],
            "existing" if existing_profile_id else "created",
            round_root,
        )
        result = RoxyApprovalControl(
            ba_token=ba_token,
            phone=inputs.phone,
            proxy_line=proxy,
            capture_root=round_root,
            existing_profile_id=existing_profile_id,
            existing_profile_name=existing_profile_name,
        ).run()
        challenged = result.get("status") == "approval_challenged"
        rotation.update(
            {
                "cursor_advanced": True,
                "reason": "approval_control_fresh_sid",
                "approval_403_quarantined": False,
            }
        )
        if challenged:
            proxy_hash, added = SignupLabInputs.quarantine_proxy(input_file, proxy)
            rotation.update(
                {
                    "approval_403_quarantined": True,
                    "quarantine_added": added,
                    "proxy_hash": proxy_hash,
                }
            )
        _persist_proxy_rotation(round_root, result, rotation)
        results.append(result)
    all_ready = len(results) == rounds and all(
        result.get("status") == "approval_ready" for result in results
    )
    safe = {
        "status": "approval_batch_ready" if all_ready else "approval_batch_failed",
        "rounds_requested": rounds,
        "rounds_completed": len(results),
        "approval_ready_count": sum(
            result.get("status") == "approval_ready" for result in results
        ),
        "all_ready": all_ready,
        "results": results,
        "capture_root": str(root),
    }
    _write_json(root / "batch-checkpoint.json", safe)
    return safe


def run_signup_lab_from_file(
    *,
    mode: str,
    input_file: str | Path,
    capture_dir: str | Path | None = None,
    protocol_transport: str = "httpx",
    keep_profile: bool = False,
    window_hold_seconds: float = 0.0,
    warmup: bool = False,
    existing_profile_id: str = "",
    existing_profile_name: str = "",
    manual_navigation: bool = False,
) -> dict[str, Any]:
    existing_control = bool(str(existing_profile_id or "").strip())
    if existing_control and mode != "reference":
        raise ValueError("existing Roxy Profile is supported only in reference mode")
    if mode == "cold-protocol" or existing_control:
        inputs = SignupLabInputs.load(input_file)
        ba_token, proxy = inputs.selection()
        proxy_index = inputs.selected_proxy_index()
        rotation: dict[str, Any] = {
            "selected_proxy_index": proxy_index,
            "next_proxy_index": inputs.next_proxy_index,
            "proxy_hash": "" if existing_control else _hash(ProxyEntry.parse(proxy).url),
            "quarantined_proxy_count": len(inputs.failed_proxy_hashes),
            "cursor_advanced": False,
            "reason": (
                "existing_profile_control_uses_persisted_proxy"
                if existing_control
                else "cold_protocol_creates_no_roxy_profile"
            ),
        }
    else:
        inputs, ba_token, proxy, rotation = SignupLabInputs.reserve_for_profile(input_file)
        rotation["cursor_advanced"] = True
        rotation["reason"] = "reserved_for_new_roxy_profile"
    root = Path(capture_dir).expanduser().resolve() if capture_dir else default_capture_root(mode).resolve()
    logger.info(
        "Signup lab start mode={} country={} ba_hash={} proxy_hash={} proxy_slot={} "
        "next_proxy_slot={} quarantined={} capture={}",
        mode,
        profile_for_phone(inputs.phone).country,
        _hash(ba_token),
        "existing-profile" if existing_control else _hash(ProxyEntry.parse(proxy).url),
        rotation["selected_proxy_index"],
        rotation["next_proxy_index"],
        rotation["quarantined_proxy_count"],
        root,
    )
    if mode == "cold-protocol":
        result = run_cold_protocol_signup(
            ba_token=ba_token,
            phone=inputs.phone,
            proxy_line=proxy,
            capture_root=root,
            protocol_transport=protocol_transport,
        )
    else:
        result = RoxySignupLab(
            mode=mode,
            ba_token=ba_token,
            phone=inputs.phone,
            proxy_line=proxy,
            capture_root=root,
            protocol_transport=protocol_transport,
            keep_profile=keep_profile,
            window_hold_seconds=window_hold_seconds,
            warmup=warmup,
            existing_profile_id=existing_profile_id,
            existing_profile_name=existing_profile_name,
            manual_navigation=manual_navigation,
        ).run()
        if existing_control:
            rotation["approval_403_quarantined"] = False
        elif _approval_document_has_status(result, 403):
            proxy_hash, added = SignupLabInputs.quarantine_proxy(input_file, proxy)
            rotation["approval_403_quarantined"] = True
            rotation["quarantine_added"] = added
            rotation["proxy_hash"] = proxy_hash
            logger.warning(
                "Signup lab approval 403 quarantined proxy SID hash={} next_proxy_slot={}",
                proxy_hash,
                rotation["next_proxy_index"],
            )
        else:
            rotation["approval_403_quarantined"] = False
    _persist_proxy_rotation(root, result, rotation)
    return result


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
