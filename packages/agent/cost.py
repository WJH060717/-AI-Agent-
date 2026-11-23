"""Conservative local USD estimate, not a provider invoice or verified market price."""

from decimal import ROUND_CEILING, Decimal

from packages.config import Settings


def estimate_cost(settings: Settings, input_tokens: int, output_tokens: int) -> int:
    prices = settings.model_input_usd_per_million, settings.model_output_usd_per_million
    if any(price is None for price in prices):
        if settings.model_test_stub and all(price is None for price in prices):
            return 0
        raise ValueError("MODEL_PRICING_UNAVAILABLE")
    # USD/million tokens multiplied by tokens is already micro-USD.
    value = Decimal(input_tokens) * prices[0] + Decimal(output_tokens) * prices[1]
    return int(value.to_integral_value(rounding=ROUND_CEILING))
