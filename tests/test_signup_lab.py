import json

import pytest

from paypal.signup_lab import SignupLabInputs, classify_signup_document


def test_signup_lab_inputs_select_without_network(tmp_path) -> None:
    source = tmp_path / "inputs.json"
    source.write_text(
        json.dumps(
            {
                "ba_tokens": ["https://www.paypal.com/agreements/approve?ba_token=BA-12345678ABCDEF"],
                "phone": "+17408803459",
                "proxies": ["proxy.test:3010:user:password"],
            }
        ),
        encoding="utf-8",
    )

    inputs = SignupLabInputs.load(source)

    assert inputs.selection() == ("BA-12345678ABCDEF", "proxy.test:3010:user:password")


def test_signup_document_requires_healthy_signup_html() -> None:
    valid = classify_signup_document(
        200,
        "text/html; charset=utf-8",
        "<html><script>window.__INITIAL_DATA__={}</script><div>checkoutweb signup</div></html>",
        "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
    )
    challenged = classify_signup_document(
        403,
        "text/html",
        "<html>DataDome Security Challenge</html>",
        "https://www.paypal.com/checkoutweb/signup?token=EC-12345678",
    )

    assert valid["valid"] is True
    assert challenged["valid"] is False
    assert set(challenged["challenge_markers"]) >= {"datadome", "security challenge"}


def test_signup_lab_rejects_missing_pool(tmp_path) -> None:
    source = tmp_path / "inputs.json"
    source.write_text(
        json.dumps({"ba_tokens": ["BA-12345678ABCDEF"], "phone": "+17408803459", "proxies": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="proxy"):
        SignupLabInputs.load(source)
