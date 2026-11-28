"""Intentionally unsafe SQL search for the local synthetic demo only."""

from pathlib import Path
from typing import Any

from demo_app.database import get_connection


def vulnerable_search_documents_for_demo(
    database_path: Path,
    query: str,
) -> list[dict[str, Any]]:
    """Demonstrate SQL injection against synthetic, local SQLite records.

    Keep this function isolated from the safe search service. It may only be
    called when `search_v1` is enabled through the explicit local demo gates.
    The `/demo/search-v1` endpoint provides a direct, visibly labeled demo path.
    """
    # Deliberately interpolated only to demonstrate why parameterized SQL matters.
    sql = f"""
        SELECT
            documents.id,
            documents.filename,
            documents.content,
            users.username,
            users.department
        FROM documents
        JOIN users ON users.id = documents.owner_id
        WHERE documents.filename LIKE '%{query}%'
           OR documents.content LIKE '%{query}%'
           OR users.username LIKE '%{query}%'
        ORDER BY documents.id
        LIMIT 50
    """  # noqa: S608

    with get_connection(database_path) as connection:
        rows = connection.execute(sql).fetchall()

    return [dict(row) for row in rows]
