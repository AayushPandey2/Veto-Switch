"""SQLite tables for incidents, proposals, approvals and audit events."""

from pathlib import Path

from demo_app.database import get_connection, initialize_database


def initialize_platform_database(database_path: Path) -> None:
    """Initialize the synthetic app database and the local platform records."""
    initialize_database(database_path)
    with get_connection(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                scenario TEXT NOT NULL,
                reporter TEXT NOT NULL,
                evidence_summary TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proposals (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(id),
                safe_flag TEXT NOT NULL,
                vulnerable_flag TEXT NOT NULL,
                target_environment TEXT NOT NULL DEFAULT 'local',
                expected_flags_json TEXT NOT NULL DEFAULT '{}',
                proposal_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                proposal_id TEXT NOT NULL UNIQUE REFERENCES proposals(id),
                decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
                actor TEXT NOT NULL,
                proposal_hash TEXT NOT NULL,
                reason TEXT,
                decided_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operation_receipts (
                id TEXT PRIMARY KEY,
                proposal_id TEXT NOT NULL UNIQUE REFERENCES proposals(id),
                receipt_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL REFERENCES incidents(id),
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS audit_events_incident_idx
                ON audit_events(incident_id, id);
            """
        )
        proposal_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(proposals)").fetchall()
        }
        if "target_environment" not in proposal_columns:
            connection.execute(
                "ALTER TABLE proposals ADD COLUMN target_environment "
                "TEXT NOT NULL DEFAULT 'local'"
            )
        if "expected_flags_json" not in proposal_columns:
            connection.execute(
                "ALTER TABLE proposals ADD COLUMN expected_flags_json "
                "TEXT NOT NULL DEFAULT '{}'"
            )
