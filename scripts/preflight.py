"""Read-only native candidate preflight; no migration, workspace creation or model call."""

import json
import os
from pathlib import Path

from alembic.runtime.migration import MigrationContext
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from packages.config import Settings
from packages.storage.database import Database
from scripts.verify_environment import EnvironmentMismatch, python_versions


def preflight(settings: Settings) -> dict:
    errors: list[str] = []
    warnings = ["WORKER_LIVENESS_NOT_VERIFIED"]
    try:
        python_versions(Path(__file__).resolve().parents[1])
    except (OSError, EnvironmentMismatch):
        errors.append("PYTHON_ENVIRONMENT_LOCK_MISMATCH")
    head = None
    database = None
    try:
        if settings.database_url is None:
            raise ValueError("missing database")
        url = make_url(settings.database_url.get_secret_value())
        if url.get_backend_name() == "sqlite" and (
            not url.database or url.database == ":memory:" or not Path(url.database).is_file()
        ):
            raise ValueError("missing database")
        database = Database(settings)
        with database.engine.connect() as connection:
            head = MigrationContext.configure(connection).get_current_revision()
        if head != "0006_d9":
            errors.append("MIGRATION_HEAD_MISMATCH")
    except (ValueError, OSError, SQLAlchemyError):
        errors.append("DATABASE_UNAVAILABLE")
    finally:
        if database:
            database.engine.dispose()
    for name, folder, access in (
        ("RAW_STORE_UNAVAILABLE", settings.raw_store, os.R_OK),
        ("STAGING_STORE_UNAVAILABLE", settings.staging_store, os.R_OK | os.W_OK),
    ):
        if not folder.is_dir() or not os.access(folder, access):
            errors.append(name)
    if (
        settings.web_dist is None
        or not (settings.web_dist / "index.html").is_file()
        or not (settings.web_dist / "assets").is_dir()
    ):
        errors.append("WEB_BUILD_UNAVAILABLE")
    if settings.app_bind not in {"127.0.0.1", "::1", "localhost"}:
        warnings.append("NON_LOOPBACK_BIND_REQUIRES_APPROVED_TLS_BOUNDARY")
    if settings.model_provider != "disabled":
        warnings.append("MODEL_CONNECTIVITY_NOT_VERIFIED")
    return {
        "ready": not errors,
        "migration_head": head,
        "model_status": "disabled" if settings.model_provider == "disabled" else "not_verified",
        "worker_status": "not_verified",
        "errors": errors,
        "warnings": warnings,
    }


def main() -> None:
    try:
        result = preflight(Settings())
    except ValueError:
        print(json.dumps({"ready": False, "errors": ["INVALID_CONFIGURATION"]}))
        raise SystemExit(1) from None
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ready"] else 1)


if __name__ == "__main__":
    main()
