"""D8 semantic configuration freeze. Historical findings retain their own config."""

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from packages.detection.r01 import R01Config
from packages.detection.r02 import R02Config
from packages.detection.r03 import R03Config
from packages.detection.r04 import R04Config
from packages.detection.r05 import R05Config
from packages.detection.r06 import R06Config

MODELS = {
    model.model_fields["id"].default: model
    for model in (R01Config, R02Config, R03Config, R04Config, R05Config, R06Config)
}
RULES = Path(__file__).resolve().parents[2] / "rules"


class FrozenRulesError(ValueError):
    pass


def config_digest(configs: dict) -> str:
    return hashlib.sha256(
        json.dumps(configs, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def load_frozen_rules(directory: Path | None = None) -> dict:
    directory = directory or RULES
    try:
        frozen = json.loads((directory / "freeze.json").read_bytes())
        configs = {
            rule: model.model_validate_json((directory / f"{rule}.json").read_bytes())
            for rule, model in MODELS.items()
        }
        values = {rule: config.model_dump(mode="json") for rule, config in configs.items()}
        if (
            frozen["version"] != "1.0.0"
            or values != frozen["configs"]
            or config_digest(values) != frozen["config_hash"]
        ):
            raise FrozenRulesError("RULE_CONFIGURATION_DRIFT")
        return configs
    except (OSError, KeyError, TypeError, ValueError, ValidationError):
        raise FrozenRulesError("RULE_CONFIGURATION_DRIFT") from None
