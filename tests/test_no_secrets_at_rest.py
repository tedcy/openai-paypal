from pathlib import Path

from paypal.local_headless import _headless_cookie_cache_enabled
from paypal.smsbower import SMSBowerActivationStore


def test_headless_cookie_cache_is_hard_disabled(monkeypatch) -> None:
    monkeypatch.setenv("PAYPAL_HEADLESS_COOKIE_CACHE", "1")
    assert _headless_cookie_cache_enabled() is False


def test_smsbower_activation_store_is_memory_only(tmp_path: Path) -> None:
    cache_path = tmp_path / "smsbower_numbers.json"
    store = SMSBowerActivationStore(cache_path)
    store.remember_success(
        activation_id="activation-secret",
        phone_number="+5500000000000",
        provider_id="provider-1",
        price=0.25,
        expires_at=4_102_444_800.0,
    )
    activation = store.reusable_activation(now=1_700_000_000.0)
    assert activation is not None
    assert activation.phone_number == "+5500000000000"
    assert not cache_path.exists()
