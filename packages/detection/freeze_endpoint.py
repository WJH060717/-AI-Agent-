"""Separate freeze for multi-Host endpoint candidates; R08 stays unchanged."""

import json
from pathlib import Path

from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.r09 import R09Config


def load_endpoint_rule(directory: Path | None = None) -> R09Config:
    directory = directory or RULES
    try:
        rule = R09Config.model_validate_json((directory / "R09.json").read_bytes())
        frozen = json.loads((directory / "cc-endpoint-freeze.json").read_bytes())
        values = {"R09": rule.model_dump(mode="json")}
        if (
            frozen["version"] != "1.0.0"
            or frozen["configs"] != values
            or frozen["config_hash"] != config_digest(values)
        ):
            raise ValueError("extension drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None
