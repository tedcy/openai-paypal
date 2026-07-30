import pytest

import web


class _DormantThread:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def start(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _isolate_jobs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(web.threading, "Thread", _DormantThread)
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
    assert "PAYPAL_ROXY_API_KEY" not in defaults
    assert "secret-value" not in defaults.values()
