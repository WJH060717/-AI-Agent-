"""Independent C&C heuristic freeze; earlier configurations are immutable."""

import json
from pathlib import Path

from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.r08 import R08Config


def load_cc_rule(directory: Path | None = None) -> R08Config:
    directory = directory or RULES
    try:
        rule = R08Config.model_validate_json((directory / "R08.json").read_bytes())
        frozen = json.loads((directory / "cc-round2-freeze.json").read_bytes())
        values = {"R08": rule.model_dump(mode="json")}
        if (
            frozen["version"] != "1.0.0"
            or frozen["configs"] != values
            or frozen["config_hash"] != config_digest(values)
        ):
            raise ValueError("extension drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None
