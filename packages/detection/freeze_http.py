"""Separately frozen extension; never rewrites the original six-rule freeze."""

import json
from pathlib import Path

from packages.detection.freeze import RULES, FrozenRulesError, config_digest
from packages.detection.r07 import R07Config


def load_http_rule(directory: Path | None = None) -> R07Config:
    directory = directory or RULES
    try:
        rule = R07Config.model_validate_json((directory / "R07.json").read_bytes())
        frozen = json.loads((directory / "http-round1-freeze.json").read_bytes())
        values = {"R07": rule.model_dump(mode="json")}
        if (
            frozen["version"] != "1.0.0"
            or frozen["configs"] != values
            or frozen["config_hash"] != config_digest(values)
        ):
            raise ValueError("extension drift")
        return rule
    except (OSError, KeyError, TypeError, ValueError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None
