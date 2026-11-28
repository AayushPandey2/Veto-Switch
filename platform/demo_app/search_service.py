"""Search operations for synthetic demonstration records."""

from pathlib import Path
from typing import Any

from demo_app.database import get_connection


def search_documents(
    database_path: Path,
    query: str,
) -> list[dict[str, Any]]:
    """Search synthetic documents using parameterized SQL."""
    with get_connection(database_path) as connection:
        rows = connection.execute(
            """
            SELECT
                documents.id,
                documents.filename,
                documents.content,
                users.username,
                users.department
            FROM documents
            JOIN users ON users.id = documents.owner_id
            WHERE documents.filename LIKE ?
               OR documents.content LIKE ?
               OR users.username LIKE ?
            ORDER BY documents.id
            LIMIT 50
            """,
            (f"%{query}%", f"%{query}%", f"%{query}%"),
        ).fetchall()

    return [dict(row) for row in rows]
