"""Compare protocol recorder output with Roxy CDP capture output."""
from __future__ import annotations

import json
import urllib.parse
from collections import defaultdict
from pathlib import Path
from typing import Any


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _stage(url: str) -> str:
    path = urllib.parse.urlsplit(url or "").path.lower()
    if "/agreements/approve" in path:
        return "approval"
    if path.rstrip("/") == "/pay":
        return "pay"
    if "/checkoutweb/signup" in path:
        return "signup"
    if "/graphql" in path:
        return "graphql"
    if "tealeaf" in path or "/v1/rum" in path or "/v2/rum" in path:
        return "telemetry"
    return "other"


def _key(method: str, url: str) -> str:
    parsed = urllib.parse.urlsplit(url or "")
    return f"{_stage(url)}:{method.upper()}:{parsed.path.rstrip('/') or '/'}"


def _cookie_names(headers: dict[str, Any]) -> list[str]:
    raw = next((str(value) for name, value in headers.items() if str(name).lower() == "cookie"), "")
    return [part.split("=", 1)[0].strip() for part in raw.split(";") if "=" in part]


def _query_keys(url: str) -> list[str]:
    return [name for name, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url or "").query, keep_blank_values=True)]


_BROWSER_EVENT_KINDS = {
    "requestWillBeSent",
    "requestWillBeSentExtraInfo",
    "responseReceived",
    "responseReceivedExtraInfo",
    "loadingFinished",
    "loadingFailed",
    "signupRequestPaused",
}


def _browser_event_kind(event: dict[str, Any]) -> str:
    explicit = str(event.get("event_kind") or "")
    if explicit:
        return explicit
    legacy = str(event.get("type") or "")
    if legacy in _BROWSER_EVENT_KINDS:
        return legacy
    # Round 1-11 placed the CDP event type before **event, so Document/XHR
    # overwrote the recorder kind. Infer those two unambiguous shapes.
    if isinstance(event.get("request"), dict):
        return "requestWillBeSent"
    if isinstance(event.get("response"), dict):
        return "responseReceived"
    return legacy


def _browser_transport_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    requests = responses = loading_failed = 0
    protocols: dict[str, int] = defaultdict(int)
    documents: list[dict[str, Any]] = []
    for event in events:
        kind = _browser_event_kind(event)
        if kind == "requestWillBeSent":
            requests += 1
        elif kind == "responseReceived":
            responses += 1
            response = dict(event.get("response") or {})
            url = str(response.get("url") or "")
            protocol = str(response.get("protocol") or "unknown")
            if urllib.parse.urlsplit(url).scheme.lower() == "https":
                protocols[protocol] += 1
            resource_type = str(event.get("resource_type") or event.get("type") or "")
            if resource_type == "Document":
                documents.append({
                    "path": urllib.parse.urlsplit(url).path or "/",
                    "status": int(response.get("status") or 0),
                    "protocol": protocol,
                })
        elif kind == "loadingFailed":
            loading_failed += 1
    return {
        "request_events": requests,
        "response_events": responses,
        "request_response_delta": requests - responses,
        "loading_failed_events": loading_failed,
        "https_protocol_counts": dict(sorted(protocols.items())),
        "main_documents": documents,
    }


def _normalize(events: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    if source == "browser":
        extra: dict[str, dict[str, Any]] = {}
        for event in events:
            if _browser_event_kind(event) == "requestWillBeSentExtraInfo":
                extra[str(event.get("requestId") or "")] = dict(event.get("headers") or {})
        for index, event in enumerate(events):
            if _browser_event_kind(event) != "requestWillBeSent":
                continue
            request = dict(event.get("request") or {})
            url = str(request.get("url") or "")
            headers = extra.get(str(event.get("requestId") or ""), dict(request.get("headers") or {}))
            output.append({
                "source": source, "index": index, "method": str(request.get("method") or "GET"),
                "url": url, "key": _key(str(request.get("method") or "GET"), url),
                "headers": headers, "header_order": list(headers), "cookie_names": _cookie_names(headers),
                "query_order": _query_keys(url), "redirect_from": bool(event.get("redirectResponse")),
                "initiator": (event.get("initiator") or {}).get("type"),
            })
    else:
        for index, event in enumerate(events):
            if event.get("type") != "request":
                continue
            url = str(event.get("url") or "")
            method = str(event.get("method") or "GET")
            headers = dict(event.get("headers") or {})
            output.append({
                "source": source, "index": index, "method": method, "url": url,
                "key": _key(method, url), "headers": headers, "header_order": list(headers),
                "cookie_names": _cookie_names(headers), "query_order": _query_keys(url),
                "redirect_from": False, "initiator": "protocol",
            })
    return output


def compare(program_root: str | Path, browser_root: str | Path) -> dict[str, Any]:
    program_root = Path(program_root).resolve()
    browser_root = Path(browser_root).resolve()
    protocol = _normalize(_read_jsonl(program_root / "network" / "events.jsonl"), "protocol")
    browser_events = _read_jsonl(browser_root / "network" / "events.jsonl")
    browser = _normalize(browser_events, "browser")
    p_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    b_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in protocol:
        p_groups[row["key"]].append(row)
    for row in browser:
        b_groups[row["key"]].append(row)
    pairs: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for key in sorted(set(p_groups) | set(b_groups)):
        p_rows, b_rows = p_groups.get(key, []), b_groups.get(key, [])
        count = max(len(p_rows), len(b_rows))
        for index in range(count):
            p_row = p_rows[index] if index < len(p_rows) else None
            b_row = b_rows[index] if index < len(b_rows) else None
            pair: dict[str, Any] = {"key": key, "ordinal": index + 1, "protocol": p_row, "browser": b_row}
            differences: list[str] = []
            if not p_row:
                differences.append("missing_in_protocol")
            elif not b_row:
                differences.append("missing_in_browser")
            else:
                if p_row["query_order"] != b_row["query_order"]:
                    differences.append("query_order")
                if p_row["cookie_names"] != b_row["cookie_names"]:
                    differences.append("cookie_names_or_order")
                p_headers = {name.lower() for name in p_row["headers"]}
                b_headers = {name.lower() for name in b_row["headers"]}
                if p_headers != b_headers:
                    differences.append("header_set")
                if [name.lower() for name in p_row["header_order"]] != [name.lower() for name in b_row["header_order"]]:
                    differences.append("header_order")
            pair["differences"] = differences
            pairs.append(pair)
            if differences:
                findings.append({"key": key, "ordinal": index + 1, "differences": differences})
    return {
        "program_root": str(program_root), "browser_root": str(browser_root),
        "protocol_requests": len(protocol), "browser_requests": len(browser),
        "browser_transport": _browser_transport_summary(browser_events),
        "pairs": pairs, "findings": findings,
        "transport_note": "Application-layer equality does not prove Chrome-equivalent TLS/HTTP2 wire behavior.",
    }


def write_markdown(report: dict[str, Any], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# PayPal Browser/Protocol Traffic Diff", "",
        f"- Protocol requests: {report.get('protocol_requests', 0)}",
        f"- Browser requests: {report.get('browser_requests', 0)}",
        f"- Findings: {len(report.get('findings') or [])}", "",
        "| Request | Ordinal | Differences |", "|---|---:|---|",
    ]
    for finding in report.get("findings") or []:
        lines.append(f"| `{finding['key']}` | {finding['ordinal']} | {', '.join(finding['differences'])} |")
    lines.extend(["", str(report.get("transport_note") or "")])
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
