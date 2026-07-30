import pytest

from paypal.country import profile_for_country
from paypal.models import generate_address, generate_card, generate_user


@pytest.mark.parametrize(
    ("country", "phone", "dial_prefix", "has_cpf"),
    [
        ("BR", "+5500000000000", "+55", True),
        ("TH", "+66000000000", "+66", False),
        ("BA", "+38700000000", "+387", False),
        ("US", "+12025550123", "+1", False),
    ],
)
def test_user_generation_is_country_aware(
    country: str,
    phone: str,
    dial_prefix: str,
    has_cpf: bool,
) -> None:
    profile = profile_for_country(country)
    user = generate_user(phone, profile)
    assert user.phone == phone
    assert user.phone_country_code == dial_prefix
    assert bool(user.cpf) is has_cpf
    assert user.first_name.isascii()
    assert user.last_name.isascii()


@pytest.mark.parametrize("country", ["BR", "TH", "BA", "US"])
def test_address_generation_matches_country(country: str) -> None:
    address = generate_address(profile_for_country(country))
    assert address.country == country
    assert address.street
    assert address.city
    assert address.postal_code
    if country == "BA":
        assert address.state is None
    if country == "US":
        assert address.state in {"IL", "WI", "MN", "MO"}
        assert len(address.state) == 2
        assert address.postal_code.isdigit()
        assert len(address.postal_code) == 5


def test_shared_ctf_card_pool_only_uses_expected_bins() -> None:
    for _ in range(250):
        card = generate_card()
        assert card.number.startswith(("414709", "516292"))
        assert not card.number.startswith("403203")
