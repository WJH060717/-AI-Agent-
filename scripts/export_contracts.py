"""Export schemas and OpenAPI. Run from the repository root."""

import json
from pathlib import Path

from apps.api.main import app
from packages.contracts.api import ApiBundle
from packages.contracts.models import ContractBundle


def main() -> None:
    target = Path("packages/contracts/generated")
    target.mkdir(parents=True, exist_ok=True)
    for name, content in (
        ("contracts.schema.json", ContractBundle.model_json_schema()),
        ("api.schema.json", ApiBundle.model_json_schema()),
        ("openapi.json", app.openapi()),
    ):
        (target / name).write_text(
            json.dumps(content, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print("Exported contracts.schema.json and openapi.json")


if __name__ == "__main__":
    main()
