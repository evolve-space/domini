import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()


def migrate_sqlite_user_columns(database_path: Path) -> None:
    if not database_path.exists():
        return

    statements = (
        "ALTER TABLE user ADD COLUMN email VARCHAR(255)",
        "ALTER TABLE user ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1",
        "ALTER TABLE user ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE user ADD COLUMN locked_until DATETIME",
        "ALTER TABLE user ADD COLUMN created_at DATETIME",
        "ALTER TABLE user ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0",
    )
    with sqlite3.connect(database_path) as connection:
        for statement in statements:
            try:
                connection.execute(statement)
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
        connection.execute(
            "UPDATE user SET created_at = ? WHERE created_at IS NULL",
            (datetime.now(timezone.utc).isoformat(),),
        )
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_user_email ON user (email)")
        connection.commit()
