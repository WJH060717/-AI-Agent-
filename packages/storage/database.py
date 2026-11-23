from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from packages.config import Settings

ROOT = Path(__file__).resolve().parents[2]


class Database:
    def __init__(self, settings: Settings):
        if settings.database_url is None:
            raise ValueError("DATABASE_URL is required for D2 business services")
        url = settings.database_url.get_secret_value()
        self.engine: Engine = create_engine(url, pool_pre_ping=True)
        if self.engine.dialect.name == "sqlite":

            @event.listens_for(self.engine, "connect")
            def foreign_keys(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")

    def migrate(self, revision: str = "head") -> None:
        config = Config()
        config.set_main_option("script_location", str(ROOT / "migrations"))
        with self.engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, revision)
