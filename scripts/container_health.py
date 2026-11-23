"""Read-only API container readiness: exact schema, archive access, and local HTTP."""

import os
from urllib.request import urlopen

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from packages.config import Settings
from packages.storage.database import Database


def check(settings: Settings) -> None:
    db = Database(settings)
    try:
        with db.engine.connect() as conn:
            if conn.execute(text("SELECT version_num FROM alembic_version")).scalar() != "0006_d9":
                raise RuntimeError("SCHEMA_NOT_READY")
    except SQLAlchemyError:
        raise RuntimeError("SCHEMA_NOT_READY") from None
    finally:
        db.engine.dispose()
    if not settings.raw_store.is_dir() or not os.access(settings.raw_store, os.R_OK):
        raise RuntimeError("ARCHIVE_NOT_READABLE")
    if not settings.staging_store.is_dir() or not os.access(settings.staging_store, os.W_OK):
        raise RuntimeError("STAGING_NOT_WRITABLE")
    response = urlopen(f"http://127.0.0.1:{settings.app_port}/api/v1/health/live", timeout=2)
    try:
        if response.status != 200:
            raise RuntimeError("HTTP_NOT_READY")
    finally:
        response.close()


if __name__ == "__main__":
    try:
        check(Settings())
    except Exception:
        raise SystemExit(1) from None
