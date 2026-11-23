from decimal import Decimal

import pytest

from packages.config import Settings


def test_configured_cost_rounds_up_and_unpriced_real_model_cannot_spend():
    from packages.agent.cost import estimate_cost

    settings = Settings(
        _env_file=None,
        model_input_usd_per_million=Decimal("0.25"),
        model_output_usd_per_million=Decimal("1.5"),
    )
    assert estimate_cost(settings, 3, 1) == 3
    assert estimate_cost(settings, 1000, 100) == 400
    with pytest.raises(ValueError, match="MODEL_PRICING_UNAVAILABLE"):
        estimate_cost(Settings(_env_file=None), 1, 1)


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-1"])
def test_invalid_model_prices_are_rejected(value):
    with pytest.raises(ValueError):
        Settings(_env_file=None, model_input_usd_per_million=value)
