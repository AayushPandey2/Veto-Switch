"""SQLite persistence for synthetic demonstration data."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

DEMO_USERS = [
    (
        user_id,
        f"demo_user_{user_id:02d}",
        f"user{user_id:02d}@example.test",
        ("Engineering", "Finance", "Operations", "Research")[
            (user_id - 1) % 4
        ],
    )
    for user_id in range(1, 21)
]


@contextmanager
def get_connection(database_path: Path) -> Iterator[sqlite3.Connection]:
    """Open a transaction-scoped connection and always close it afterward."""
    database_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database_path)

    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path: Path) -> None:
    """Create the synthetic demo schema."""
    with get_connection(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                department TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                content TEXT NOT NULL,
                is_public INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (owner_id) REFERENCES users(id),
                UNIQUE (owner_id, filename)
            );

            CREATE TABLE IF NOT EXISTS demo_feature_flags (
                flag_name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS demo_identity_feature_flags (
                identity TEXT NOT NULL,
                flag_name TEXT NOT NULL,
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(identity, flag_name)
            );

            CREATE TABLE IF NOT EXISTS demo_request_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                route TEXT NOT NULL,
                identity TEXT,
                variant TEXT NOT NULL,
                outcome TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS demo_request_events_created_idx "
            "ON demo_request_events(created_at DESC)"
        )


def get_demo_flag_override(database_path: Path, flag_name: str) -> bool | None:
    """Read an explicit local API override, if one has been recorded."""
    with get_connection(database_path) as connection:
        row = connection.execute(
            "SELECT enabled FROM demo_feature_flags WHERE flag_name = ?",
            (flag_name,),
        ).fetchone()

    if row is None:
        return None
    return bool(row["enabled"])


def get_demo_identity_flag_override(
    database_path: Path,
    identity: str,
    flag_name: str,
) -> bool | None:
    with get_connection(database_path) as connection:
        row = connection.execute(
            "SELECT enabled FROM demo_identity_feature_flags WHERE identity = ? AND flag_name = ?",
            (identity, flag_name),
        ).fetchone()
    return None if row is None else bool(row["enabled"])


def set_demo_flag_overrides(
    database_path: Path,
    values: dict[str, bool],
    *,
    actor: str,
) -> None:
    """Persist local demo flag states with a timestamp and operator label."""
    updated_at = datetime.now(UTC).isoformat()
    with get_connection(database_path) as connection:
        connection.executemany(
            """
            INSERT INTO demo_feature_flags (flag_name, enabled, updated_by, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(flag_name) DO UPDATE SET
                enabled = excluded.enabled,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            [
                (flag_name, int(enabled), actor, updated_at)
                for flag_name, enabled in values.items()
            ],
        )


def set_demo_identity_flag_overrides(
    database_path: Path,
    values: dict[tuple[str, str], bool],
    *,
    actor: str,
) -> None:
    updated_at = datetime.now(UTC).isoformat()
    with get_connection(database_path) as connection:
        connection.executemany(
            """
            INSERT INTO demo_identity_feature_flags
                (identity, flag_name, enabled, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(identity, flag_name) DO UPDATE SET
                enabled = excluded.enabled,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            [
                (identity, flag_name, int(enabled), actor, updated_at)
                for (identity, flag_name), enabled in values.items()
            ],
        )


def replace_demo_identity_flag_overrides(
    database_path: Path,
    flag_name: str,
    values: dict[str, bool | None],
    *,
    actor: str,
) -> None:
    """Replace a flag's seeded identity overrides, where None means inherit."""
    updated_at = datetime.now(UTC).isoformat()
    with get_connection(database_path) as connection:
        connection.execute(
            "DELETE FROM demo_identity_feature_flags WHERE flag_name = ?",
            (flag_name,),
        )
        connection.executemany(
            """
            INSERT INTO demo_identity_feature_flags
                (identity, flag_name, enabled, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (identity, flag_name, int(enabled), actor, updated_at)
                for identity, enabled in values.items()
                if enabled is not None
            ],
        )


def delete_demo_identity_flag_override(
    database_path: Path,
    identity: str,
    flag_name: str,
) -> None:
    with get_connection(database_path) as connection:
        connection.execute(
            "DELETE FROM demo_identity_feature_flags WHERE identity = ? AND flag_name = ?",
            (identity, flag_name),
        )


def record_demo_request(
    database_path: Path,
    *,
    route: str,
    identity: str | None,
    variant: str,
    outcome: str,
    status_code: int,
) -> None:
    with get_connection(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO demo_request_events
                (route, identity, variant, outcome, status_code, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (route, identity, variant, outcome, status_code, datetime.now(UTC).isoformat()),
        )
        if cursor.lastrowid and cursor.lastrowid % 256 == 0:
            connection.execute(
                "DELETE FROM demo_request_events WHERE id NOT IN "
                "(SELECT id FROM demo_request_events ORDER BY id DESC LIMIT 10000)"
            )


def get_demo_telemetry(database_path: Path, *, limit: int = 100) -> dict:
    with get_connection(database_path) as connection:
        summary = connection.execute(
            """
            SELECT route, variant, outcome, status_code, COUNT(*) AS requests
            FROM demo_request_events
            GROUP BY route, variant, outcome, status_code
            ORDER BY route, variant, outcome, status_code
            """
        ).fetchall()
        recent = connection.execute(
            """
            SELECT id, route, identity, variant, outcome, status_code, created_at
            FROM demo_request_events ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {
        "data_label": "DEMO / SYNTHETIC DATA",
        "simulation": True,
        "summary": [dict(row) for row in summary],
        "recent": [dict(row) for row in recent],
    }


def seed_demo_data(database_path: Path) -> None:
    """Insert deterministic synthetic users and documents."""
    with get_connection(database_path) as connection:
        connection.executemany(
            """
            INSERT OR IGNORE INTO users
                (id, username, email, department)
            VALUES (?, ?, ?, ?)
            """,
            DEMO_USERS,
        )

        connection.executemany(
            """
            INSERT OR IGNORE INTO documents
                (id, owner_id, filename, content, is_public)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    user_id,
                    user_id,
                    f"report_{user_id:02d}.txt",
                    f"Synthetic report for demo_user_{user_id:02d}. "
                    "This record contains demonstration-only information.",
                    user_id % 2,
                )
                for user_id in range(1, 21)
            ],
        )


def get_user_count(database_path: Path) -> int:
    """Return the number of seeded demonstration users."""
    with get_connection(database_path) as connection:
        result = connection.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()

    return int(result[0])


def get_document_count(database_path: Path) -> int:
    """Return the number of seeded demonstration documents."""
    with get_connection(database_path) as connection:
        result = connection.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()

    return int(result[0])
