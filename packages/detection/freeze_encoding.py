"""Independent non-text query rule freeze; old rule freezes remain unchanged."""

import json
from pathlib import Path

from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.r11 import R11Config


def load_encoding_rule(directory: Path | None = None) -> R11Config:
    directory = directory or RULES
    try:
        rule = R11Config.model_validate_json((directory / "R11.json").read_bytes())
        frozen = json.loads((directory / "cc-encoding-freeze.json").read_bytes())
        values = {"R11": rule.model_dump(mode="json")}
        if (
            frozen["version"] != rule.version
            or frozen["configs"] != values
            or frozen["config_hash"] != config_digest(values)
        ):
            raise ValueError("extension drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None
