import inspect
from pathlib import Path

import pytest

import web
from paypal.proxy import ProxyConfig, ProxyEntry


class _DormantThread:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def start(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _isolate_jobs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(web.threading, "Thread", _DormantThread)
    monkeypatch.setattr(
        web,
        "build_automatic_proxy_config",
        lambda country: ProxyConfig(
            enabled=True,
            entry=ProxyEntry(
                host="proxy.test",
                port=3010,
                username=f"account-region-{country}-sid-TestSid1-t-120",
                password="proxy-password",
            ),
        ),
    )
    with web.JOBS_LOCK:
        web.JOBS.clear()
    yield
    with web.JOBS_LOCK:
        web.JOBS.clear()


@pytest.mark.parametrize(
    "phone",
    ["+5500000000000", "+66000000000", "+38700000000", "+12025550123"],
)
def test_web_create_job_accepts_all_country_phones_without_starting_flow(phone: str) -> None:
    job = web.create_job(
        owner_device_id=f"test-{phone}",
        ba_token=(
            "https://www.paypal.com/agreements/approve"
            "?ba_token=BA-TESTTOKEN123456"
        ),
        phone=phone,
        debug=False,
        max_card_attempts=5,
    )
    assert job.ba_token == "BA-TESTTOKEN123456"
    assert job.phone == phone
    assert job.status == "queued"
    assert f"region={web.profile_for_phone(phone).country}" in job.proxy_label
    assert "sid=TestSid1" in job.proxy_label
    assert "proxy-password" not in job.proxy_label


def test_web_create_job_rejects_unsupported_phone_prefix() -> None:
    with pytest.raises(ValueError, match=r"expected \+55, \+66, \+387 or \+1"):
        web.create_job(
            owner_device_id="test-invalid",
            ba_token="BA-TESTTOKEN123456",
            phone="+33123456789",
            debug=False,
            max_card_attempts=5,
        )


def test_web_smsbower_without_phone_defaults_to_br(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web, "_build_smsbower_provider", lambda enabled: object())
    job = web.create_job(
        owner_device_id="test-smsbower",
        ba_token="BA-TESTTOKEN123456",
        phone="",
        debug=False,
        max_card_attempts=5,
        sms_provider="smsbower",
    )
    assert job.phone == ""
    assert job.sms_provider == "smsbower"


def test_runtime_defaults_read_roxy_modes_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAYPAL_FINGERPRINT_SOURCE", "roxy")
    monkeypatch.setenv("PAYPAL_DATADOME_MODE", "roxy")
    monkeypatch.setenv("PAYPAL_MTR_RUNTIME", "roxy")
    monkeypatch.setenv("PAYPAL_RISK_SIGNALS_MODE", "roxy")

    assert web.runtime_defaults() == {
        "execution_mode": "standard",
        "fingerprint_source": "roxy",
        "datadome_mode": "roxy",
        "mtr_runtime": "roxy",
        "risk_signals_mode": "roxy",
    }


def test_runtime_defaults_do_not_return_unrelated_environment_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAYPAL_ROXY_API_KEY", "secret-value")
    monkeypatch.setenv("PAYPAL_FINGERPRINT_SOURCE", "invalid")

    defaults = web.runtime_defaults()

    assert defaults["fingerprint_source"] == "headless"
    assert defaults["execution_mode"] == "standard"
    assert "PAYPAL_ROXY_API_KEY" not in defaults
    assert "secret-value" not in defaults.values()


def test_protocol_signup_overrides_roxy_runtime_and_requires_manual_phone() -> None:
    job = web.create_job(
        owner_device_id="test-protocol-signup",
        ba_token="BA-TESTTOKEN123456",
        phone="+38761123456",
        debug=False,
        max_card_attempts=5,
        execution_mode="protocol_signup",
        fingerprint_source="client-forged-runtime",
        datadome_mode="client-forged-runtime",
        mtr_runtime="client-forged-runtime",
        risk_signals_mode="client-forged-runtime",
    )

    assert job.execution_mode == "protocol_signup"
    assert job.fingerprint_source == "random"
    assert job.datadome_mode == "protocol"
    assert job.mtr_runtime == "python_generated"
    assert job.risk_signals_mode == "protocol"
    assert job.protocol_transport == "curl-chrome-http1"

    with pytest.raises(ValueError, match="必须填写 E.164"):
        web.create_job(
            owner_device_id="test-protocol-signup-empty",
            ba_token="BA-TESTTOKEN123456",
            phone="",
            debug=False,
            max_card_attempts=5,
            execution_mode="protocol_signup",
            sms_provider="smsbower",
        )

    with pytest.raises(ValueError, match="不使用 SMSBower"):
        web.create_job(
            owner_device_id="test-protocol-signup-sms",
            ba_token="BA-TESTTOKEN123456",
            phone="+5500000000000",
            debug=False,
            max_card_attempts=5,
            execution_mode="protocol_signup",
            sms_provider="smsbower",
        )


def test_standard_mode_keeps_runtime_choices_and_rejects_unknown_execution() -> None:
    job = web.create_job(
        owner_device_id="test-standard-runtime",
        ba_token="BA-TESTTOKEN123456",
        phone="+12025550123",
        debug=False,
        max_card_attempts=5,
        fingerprint_source="roxy",
        datadome_mode="roxy",
        mtr_runtime="roxy",
        risk_signals_mode="roxy",
    )
    assert job.execution_mode == "standard"
    assert job.fingerprint_source == "roxy"
    assert job.protocol_transport == ""

    with pytest.raises(ValueError, match="执行路线不正确"):
        web.create_job(
            owner_device_id="test-unknown-mode",
            ba_token="BA-TESTTOKEN123456",
            phone="+12025550123",
            debug=False,
            max_card_attempts=5,
            execution_mode="unknown",
        )


def test_protocol_signup_runner_stops_before_full_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, object] = {}

    class _Flow:
        def __init__(self, *args, **kwargs) -> None:
            calls["kwargs"] = kwargs

        def run_until_signup(self):
            calls["run_until_signup"] = True
            return {
                "status": "protocol_signup_ready",
                "http_status": 200,
                "signup_url": (
                    "https://www.paypal.com/checkoutweb/signup"
                    "?ba_token=BA-RAWVALUE123&token=EC-RAWVALUE123"
                ),
                "classification": {"valid": True},
            }

        def run(self):
            raise AssertionError("protocol_signup must not execute the full flow")

    monkeypatch.setattr(web, "WebPayPalFlow", _Flow)
    job = web.create_job(
        owner_device_id="test-protocol-runner",
        ba_token="BA-TESTTOKEN123456",
        phone="+38761123456",
        debug=False,
        max_card_attempts=5,
        execution_mode="protocol_signup",
    )

    web.run_job(job)

    kwargs = calls["kwargs"]
    assert isinstance(kwargs, dict)
    assert calls["run_until_signup"] is True
    assert kwargs["protocol_transport"] == "curl-chrome-http1"
    assert kwargs["protocol_impersonate"] == "chrome136"
    assert kwargs["fingerprint_source"] == "random"
    assert kwargs["datadome_mode"] == "protocol"
    assert kwargs["mtr_runtime"] == "python_generated"
    assert kwargs["risk_signals_mode"] == "protocol"
    assert kwargs["browser_profile_seed"]["chrome_major"] == 136
    assert kwargs["browser_profile_seed"]["ua_client_hints_enabled"] is False
    assert job.status == "completed"
    assert job.stage == "纯协议 Signup 200，已安全停止"
    assert job.result["roxy_api_calls"] == 0
    assert job.result["stopped_before_signup_mutation"] is True

    public = job.to_dict()
    assert "BA-RAWVALUE123" not in public["result"]["signup_url"]
    assert "EC-RAWVALUE123" not in public["result"]["signup_url"]


def test_protocol_signup_failure_retains_sanitized_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Flow:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def run_until_signup(self):
            return {
                "status": "failed",
                "error": "PROTOCOL_APPROVAL_APPLICATION_MISSING",
                "signup_url": "https://www.paypal.com/checkoutweb/genericError?ba_token=BA-RAWVALUE123",
                "classification": {"valid": False},
            }

    monkeypatch.setattr(web, "WebPayPalFlow", _Flow)
    job = web.create_job(
        owner_device_id="test-protocol-failed",
        ba_token="BA-TESTTOKEN123456",
        phone="+38761123456",
        debug=False,
        max_card_attempts=5,
        execution_mode="protocol_signup",
    )

    web.run_job(job)

    assert job.status == "failed"
    assert job.result is not None
    public = job.to_dict()
    assert public["result"]["classification"] == {"valid": False}
    assert "BA-RAWVALUE123" not in public["result"]["signup_url"]


def test_protocol_full_runner_uses_full_flow_without_roxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, object] = {}

    class _Flow:
        def __init__(self, *args, **kwargs) -> None:
            calls["kwargs"] = kwargs
            self.job = kwargs["job"]

        def run(self):
            calls["run"] = True
            calls["otp"] = self.job.wait_for_input("请输入6位短信验证码")
            return {"status": "success"}

        def run_until_signup(self):
            raise AssertionError("protocol_full must execute the full flow")

    monkeypatch.setattr(web, "WebPayPalFlow", _Flow)
    job = web.create_job(
        owner_device_id="test-protocol-full",
        ba_token="BA-TESTTOKEN123456",
        phone="+12025550123",
        debug=False,
        max_card_attempts=5,
        execution_mode="protocol_full",
    )
    job.submit_input("123456")

    web.run_job(job)

    assert calls["run"] is True
    assert calls["otp"] == "123456"
    assert job.status == "completed"
    assert job.result["execution_mode"] == "protocol_full"
    assert job.result["roxy_api_calls"] == 0
    assert job.result["protocol_transport"] == "curl-chrome-http1"


def test_web_ui_exposes_and_locks_protocol_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    html = (root / "web_static" / "index.html").read_text(encoding="utf-8")
    javascript = (root / "web_static" / "app.js").read_text(encoding="utf-8")

    assert 'value="standard"' in html
    assert 'value="protocol_signup"' in html
    assert 'value="protocol_full"' in html
    assert 'execution_mode: executionMode' in javascript
    assert 'fingerprint_source: "random"' in javascript
    assert 'datadome_mode: "protocol"' in javascript
    assert 'mtr_runtime: "python_generated"' in javascript
    assert '$("#smsbowerEnabled").disabled = signupProbe' in javascript
    assert 'id="automaticProxyHint"' in html
    assert 'id="proxyMode"' not in html
    assert 'id="proxyUrl"' not in html
    assert "PAYPAL_PROXY_URL" not in html
    assert "proxy_url:" not in javascript
    assert "syncProxyFields" not in javascript


def test_web_job_api_has_no_client_proxy_parameters() -> None:
    parameters = inspect.signature(web.create_job).parameters

    assert "proxy_enabled" not in parameters
    assert "proxy_mode" not in parameters
    assert "proxy_url" not in parameters
