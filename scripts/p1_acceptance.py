"""Offline acceptance readiness. No model calls, migrations, signing or deployment."""

import argparse
import hashlib
import json
import os
import subprocess
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from packages.config import Settings
from packages.contracts.models import Contract

ROOT = Path(__file__).resolve().parents[1]
MODEL_FIELDS = {
    "model_provider",
    "model_base_url",
    "model_name",
    "model_api_key",
    "model_test_stub",
    "model_thinking",
    "model_plan_fact_limit",
    "model_timeout_seconds",
    "model_output_tokens_per_call",
    "model_input_usd_per_million",
    "model_output_usd_per_million",
    "model_price_version",
    "agent_max_cost_microusd",
}
REQUIRED = [
    "model_provider",
    "model_base_url",
    "model_name",
    "model_api_key",
    "model_input_usd_per_million",
    "model_output_usd_per_million",
    "model_price_version",
    "agent_max_cost_microusd",
]


class ModelReadiness(Contract):
    status: Literal["missing", "incomplete", "configuration_ready"]
    errors: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=lambda: list(REQUIRED))
    per_run_budget_microusd: int | None = None
    connectivity_verified: Literal[False] = False
    prices_independently_verified: Literal[False] = False
    real_llm_accepted: Literal[False] = False


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("DUPLICATE_CONFIG_KEY")
        result[name] = value
    return result


def model_readiness(path: Path | None) -> ModelReadiness:
    if path is None:
        return ModelReadiness(status="missing", errors=["PRIVATE_MODEL_CONFIGURATION_REQUIRED"])
    try:
        with path.open("rb") as stream:
            raw = stream.read(32769)
        if len(raw) > 32768:
            raise ValueError("CONFIG_TOO_LARGE")
        values = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(values, dict) or set(values) - MODEL_FIELDS:
            raise ValueError("CONFIG_FIELDS_INVALID")
        # Explicit defaults for every field prevent inherited shell/.env credentials.
        defaults = {
            name: field.get_default(call_default_factory=True)
            for name, field in Settings.model_fields.items()
        }
        settings = Settings(_env_file=None, **(defaults | values))
    except (OSError, ValueError, TypeError):
        # Pydantic/JSON exception strings may contain the private input. Never echo them.
        return ModelReadiness(status="incomplete", errors=["PRIVATE_CONFIGURATION_INVALID"])
    errors = []
    if settings.model_provider != "compatible":
        errors.append("MODEL_PROVIDER_NOT_ENABLED")
    if not settings.model_api_key or not settings.model_api_key.get_secret_value().strip():
        errors.append("MODEL_API_KEY_REQUIRED")
    if not settings.model_name or not settings.model_name.strip():
        errors.append("MODEL_NAME_REQUIRED")
    if not settings.model_base_url:
        errors.append("MODEL_BASE_URL_REQUIRED")
    if settings.model_test_stub:
        errors.append("PROTOCOL_STUB_IS_NOT_REAL_MODEL")
    if (
        settings.model_input_usd_per_million is None
        or settings.model_output_usd_per_million is None
    ):
        errors.append("MODEL_PRICES_REQUIRED")
    if not settings.model_price_version.strip() or settings.model_price_version == "unconfigured":
        errors.append("MODEL_PRICE_VERSION_REQUIRED")
    if settings.agent_max_cost_microusd <= 0:
        errors.append("APPROVED_POSITIVE_BUDGET_REQUIRED")
    return ModelReadiness(
        status="incomplete" if errors else "configuration_ready",
        errors=errors,
        per_run_budget_microusd=settings.agent_max_cost_microusd,
    )


def probe_command(argv: list[str], env: dict[str, str], cwd: Path) -> int:
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return -1


def readiness_report(
    root: Path,
    model_config: Path | None,
    probe: Callable[[list[str], dict[str, str], Path], int] = probe_command,
) -> dict:
    # Only offline tooling imports eval. No application/worker import path reaches this module.
    from eval.freeze import verify_freeze

    env = os.environ.copy()
    env.update(
        TRACE_DATABASE_URL="postgresql+psycopg://trace_app:placeholder@db:5432/trace",
        TRACE_OWNER_PASSWORD_FILE=str(root / ".tools/not-a-real-owner-password"),
    )
    compose = root / "infra/compose.p1.yaml"
    compose_code = probe(["docker", "compose", "-f", str(compose), "config", "--quiet"], env, root)
    engine_code = probe(["docker", "info", "--format", "{{.ServerVersion}}"], env, root)
    try:
        readiness = verify_freeze(root, json.loads((root / "eval/freeze-d9.json").read_bytes()))
        formal = {
            name: readiness[name]
            for name in [
                "planned",
                "prepared",
                "reviewed_runs",
                "data_collection_complete",
                "labels_review_complete",
            ]
        }
        formal["inventory_verified"] = True
    except (OSError, ValueError, KeyError):
        formal = {"inventory_verified": False, "error": "FORMAL_INPUTS_UNAVAILABLE_OR_CHANGED"}
    status = json.loads((root / "docs/p1-defects.json").read_bytes())
    bound = [
        "pyproject.toml",
        "requirements-dev.lock",
        "infra/compose.p1.yaml",
        "rules/freeze.json",
        "eval/freeze-d9.json",
        "docs/p1-defects.json",
        "release/p1-scale-freeze-01.json",
        "scripts/p1_acceptance.py",
    ]
    return {
        "version": "p1-acceptance-readiness@1.0.0",
        "measured_at": datetime.now(UTC).isoformat(),
        "application_version": tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]["version"],
        "model": model_readiness(model_config).model_dump(),
        "formal_data": formal,
        "deployment": {
            "compose_config_valid": compose_code == 0,
            "engine_available": engine_code == 0,
            "image_build_verified": False,
            "container_start_verified": False,
            "non_author_verified": False,
        },
        "open_p1": status["open_p1"],
        "human_signatures": [],
        "release_ready": False,
        "required_human_checks": [
            "real_llm_and_bill",
            "independent_inputs_and_dual_review",
            "non_author_restore",
            "clean_machine_start",
            "physical_disconnect_and_rehearsal",
        ],
        "input_hashes": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in bound
            if (root / name).is_file()
        },
    }


def write_report(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-config", type=Path, help="Private JSON; read-only, never uploaded")
    parser.add_argument("--output", type=Path, required=True, help="NEW public readiness JSON")
    args = parser.parse_args()
    try:
        result = readiness_report(ROOT, args.model_config)
        write_report(args.output, result)
    except (OSError, ValueError, KeyError):
        print(json.dumps({"error": "READINESS_INPUT_OR_OUTPUT_INVALID"}))
        raise SystemExit(1) from None
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(2)  # Local readiness cannot attest external acceptance or human signatures.


if __name__ == "__main__":
    main()
