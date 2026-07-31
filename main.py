#!/usr/bin/env python3
"""PayPal Billing Agreement approval automation.

Usage:
    python main.py --ba-token BA-xxx --phone +12025550123
"""
import argparse
import importlib
import json
import os
import sys
from pathlib import Path
from loguru import logger

from paypal.models import generate_user, generate_card, generate_address
from paypal.country import parse_ba_token, profile_for_country, profile_for_phone
from paypal.flow import PayPalFlow
from paypal.proxy import build_proxy_config
from paypal.session import sanitize_for_log
from paypal.traffic_recorder import close_global_traffic_recorder, reset_global_traffic_recorder


def _smsbower_module():
    return importlib.import_module("paypal.smsbower")


def _smsbower_enabled() -> bool:
    return bool(getattr(_smsbower_module(), "smsbower_enabled")())


def _build_smsbower_provider(enabled: bool, api_key: str | None):
    return getattr(_smsbower_module(), "build_smsbower_provider")(
        enabled=enabled,
        api_key=api_key,
    )


def _sanitized_console_sink(message) -> None:
    record = message.record
    safe_message = sanitize_for_log({"body": str(record["message"])})["body"]
    timestamp = record["time"].strftime("%H:%M:%S")
    sys.stderr.write(f"{timestamp} | {record['level'].name:<8} | {safe_message}\n")


def main():
    parser = argparse.ArgumentParser(
        description="PayPal Billing Agreement Approval Automation"
    )
    parser.add_argument(
        "--ba-token", required=False, default="",
        help="Billing Agreement token or agreements/approve URL"
    )
    parser.add_argument(
        "--signup-lab",
        choices=["reference", "handoff", "cold-protocol"],
        default=None,
        help="Stop at checkoutweb/signup for browser/protocol comparison",
    )
    parser.add_argument(
        "--protocol-transport",
        choices=["httpx", "curl-chrome"],
        default="httpx",
        help="HTTP transport used for signup lab protocol requests",
    )
    parser.add_argument(
        "--lab-input-file",
        default="var/signup-lab/inputs.json",
        help="Git-ignored JSON containing BA, phone and proxy pools",
    )
    parser.add_argument(
        "--capture-dir",
        default=None,
        help="Signup lab raw capture directory",
    )
    parser.add_argument(
        "--keep-roxy-profile",
        action="store_true",
        help="Keep the profile created by this signup lab run",
    )
    parser.add_argument(
        "--roxy-window-hold-seconds",
        type=float,
        default=0.0,
        help="Keep the headed Roxy/CDP window open before closing the lab result",
    )
    parser.add_argument(
        "--phone",
        default="",
        help="E.164 phone; supported prefixes: +55, +66, +387 and +1"
    )
    parser.add_argument(
        "--smsbower",
        action="store_true",
        help="Use SMSBower to acquire and receive the PayPal Brazil SMS automatically",
    )
    parser.add_argument(
        "--smsbower-api-key",
        default=None,
        help="SMSBower API key. Defaults to SMSBOWER_API_KEY or PAYPAL_SMSBOWER_API_KEY from .env/environment",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--max-card-attempts",
        type=int,
        default=5,
        help="Max SignUpNewMember retries with fresh generated Visa/MasterCard when addCard fails",
    )
    parser.add_argument(
        "--max-flow-attempts",
        type=int,
        default=1,
        help="Max full-flow attempts; 1 means no full-flow retry",
    )
    parser.add_argument(
        "--max-authorize-attempts",
        type=int,
        default=2,
        help="Authorize attempts (capped at 2: initial request plus one context refresh)",
    )
    parser.add_argument(
        "--card-retry-delay",
        type=float,
        default=6.0,
        help="Seconds to wait before generating/submitting the next card after a card rejection",
    )
    parser.add_argument(
        "--card-retry-jitter",
        type=float,
        default=2.0,
        help="Extra random seconds added to card retry delay",
    )
    proxy_group = parser.add_mutually_exclusive_group()
    proxy_group.add_argument(
        "--proxy",
        dest="proxy_enabled",
        action="store_true",
        default=None,
        help="Enable outbound proxy from PAYPAL_PROXY_URL or PAYPAL_PROXY_POOL for this run",
    )
    proxy_group.add_argument(
        "--no-proxy",
        dest="proxy_enabled",
        action="store_false",
        help="Disable outbound proxy for this run",
    )
    parser.add_argument(
        "--proxy-index",
        type=int,
        default=None,
        help="Use a specific PAYPAL_PROXY_POOL entry (0-based). Default: random when proxy is enabled",
    )
    parser.add_argument(
        "--proxy-url",
        default=None,
        help="Use a custom/chained proxy URL or host:port:user:pass line for this run",
    )
    parser.add_argument(
        "--record-traffic",
        action="store_true",
        help="Test mode: record all program-side outbound requests/responses for offline diffing",
    )
    parser.add_argument(
        "--traffic-dir",
        default=None,
        help="Output directory for --record-traffic. Default: captures/program-paypal-YYYYMMDD-HHMMSS",
    )
    parser.add_argument(
        "--compare-roxy-capture",
        default=None,
        help="After --record-traffic run, compare program traffic with this Roxy capture dir",
    )
    parser.add_argument(
        "--fingerprint-source",
        choices=["random", "program", "python", "synthetic", "roxy", "browser", "headless", "local_headless", "playwright", "local_playwright", "auto"],
        default=None,
        help="Browser fingerprint source: random/program Python generator, roxy RoxyBrowser runtime, local headless Playwright, or auto",
    )
    parser.add_argument(
        "--datadome-mode",
        choices=["protocol", "edge", "roxy", "browser", "headless", "local_headless", "playwright", "local_playwright", "auto", "off"],
        default=None,
        help="DataDome mode: protocol edge simulation, roxy browser runtime, local headless Playwright, auto, or off",
    )
    parser.add_argument(
        "--mtr-runtime",
        choices=["python_generated", "python", "protocol", "roxy", "browser", "headless", "local_headless", "playwright", "local_playwright", "auto", "block", "off"],
        default=None,
        help="MTR sealedResult source: python_generated protocol template, roxy browser runtime, local headless Playwright, auto, block, or off",
    )
    parser.add_argument(
        "--risk-signals-mode",
        choices=["protocol", "python", "synthetic", "template", "roxy", "browser", "headless", "local_headless", "playwright", "local_playwright", "auto", "off"],
        default=None,
        help="Signup-context browser risk source: roxy browser runtime, local headless Playwright, auto, or off",
    )

    args = parser.parse_args()

    logger.remove()
    logger.add(_sanitized_console_sink, level="DEBUG" if args.debug else "INFO")

    if args.signup_lab in {"reference", "handoff", "cold-protocol"}:
        from paypal.signup_lab import run_signup_lab_from_file

        result = run_signup_lab_from_file(
            mode=args.signup_lab,
            input_file=args.lab_input_file,
            capture_dir=args.capture_dir,
            protocol_transport=args.protocol_transport,
            keep_profile=args.keep_roxy_profile,
            window_hold_seconds=args.roxy_window_hold_seconds,
        )
        print(json.dumps(sanitize_for_log(result), indent=2, ensure_ascii=False))
        sys.exit(0 if result.get("status") in {"browser_signup_ready", "protocol_signup_ready"} else 1)

    if not args.ba_token:
        parser.error("--ba-token is required outside signup lab input-file mode")
    try:
        args.ba_token = parse_ba_token(args.ba_token)
    except ValueError as exc:
        parser.error(str(exc))
    if args.datadome_mode:
        os.environ["PAYPAL_DATADOME_MODE"] = args.datadome_mode
    if args.mtr_runtime:
        os.environ["PAYPAL_MTR_RUNTIME"] = args.mtr_runtime
    if args.risk_signals_mode:
        os.environ["PAYPAL_RISK_SIGNALS_MODE"] = args.risk_signals_mode

    traffic_recorder = None
    if args.record_traffic or args.traffic_dir or args.compare_roxy_capture:
        os.environ["PAYPAL_TRAFFIC_RECORD"] = "1"
        traffic_recorder = reset_global_traffic_recorder(args.traffic_dir)
        logger.info("Program traffic recording enabled: {}", traffic_recorder.root)

    proxy_config = build_proxy_config(
        enabled=args.proxy_enabled,
        index=args.proxy_index,
        proxy_url=args.proxy_url,
    )
    sms_provider_requested = bool(args.smsbower or args.smsbower_api_key or _smsbower_enabled())
    sms_provider = _build_smsbower_provider(
        enabled=sms_provider_requested,
        api_key=args.smsbower_api_key,
    )
    if not args.phone and sms_provider is None:
        parser.error("--phone is required unless --smsbower or SMSBOWER_ENABLED=1 is set")

    try:
        country_profile = (
            profile_for_phone(args.phone)
            if args.phone
            else profile_for_country("BR")
        )
    except ValueError as exc:
        parser.error(str(exc))
    if sms_provider is not None and country_profile.country != "BR":
        parser.error("SMSBower mode only supports Brazil (+55)")

    user = generate_user(args.phone or "+5500000000000", country_profile)
    card = generate_card(proxy_url=proxy_config.url)
    address = generate_address(country_profile)

    logger.info(f"User: {user.first_name} {user.last_name}")
    logger.info("Email: {}", sanitize_for_log({"email": user.email})["email"])
    if sms_provider is None:
        logger.info("Phone: {}", sanitize_for_log({"phone": user.phone})["phone"])
    else:
        logger.info("Phone: SMSBower auto mode will reserve a Brazil PayPal number before OTP")
    logger.info("CPF: {}", "<redacted>" if user.cpf else "not applicable")
    logger.info("DOB: <redacted>")
    logger.info(
        "Card: {} exp={} cvv=<redacted>",
        sanitize_for_log({"cardNumber": card.number})["cardNumber"],
        card.expiry,
    )
    logger.info("Address generated: {}, {}-{}", address.district, address.city, address.state)
    logger.info(f"Proxy: {proxy_config.label}")

    try:
        flow = PayPalFlow(
            ba_token=args.ba_token,
            user=user,
            card=card,
            address=address,
            max_card_attempts=args.max_card_attempts,
            max_flow_attempts=args.max_flow_attempts,
            max_authorize_attempts=args.max_authorize_attempts,
            card_retry_delay_seconds=args.card_retry_delay,
            card_retry_jitter_seconds=args.card_retry_jitter,
            proxy_config=proxy_config,
            fingerprint_source=args.fingerprint_source,
            datadome_mode=args.datadome_mode,
            mtr_runtime=args.mtr_runtime,
            risk_signals_mode=args.risk_signals_mode,
            sms_provider=sms_provider,
            country_profile=country_profile,
        )
        result = flow.run()
    finally:
        close_global_traffic_recorder()

    if args.compare_roxy_capture and traffic_recorder is not None:
        try:
            from tools.compare_paypal_traffic import compare, write_markdown

            report = compare(
                traffic_recorder.root,
                Path(args.compare_roxy_capture).expanduser().resolve(),
            )
            report_path = traffic_recorder.root / "traffic_diff_report.json"
            report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            write_markdown(report, report_path.with_suffix(".md"))
            logger.info("Traffic diff report saved: {}", report_path)
            if report.get("findings"):
                logger.warning(
                    "Traffic diff findings: {}",
                    json.dumps(report.get("findings"), ensure_ascii=False, indent=2),
                )
        except Exception as exc:
            logger.warning("Traffic diff failed: {}", exc)

    print("\n" + "=" * 60)
    print("RESULT:")
    print(json.dumps(sanitize_for_log(result), indent=2, ensure_ascii=False))
    print("=" * 60)

    if result.get("status") == "success":
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
