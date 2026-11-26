"""SQLite persistence for synthetic demonstration data."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
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
            """
        )


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
