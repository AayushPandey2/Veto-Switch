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
                finding_json TEXT NOT NULL DEFAULT '{}',
                source_finding_id TEXT,
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

            CREATE TABLE IF NOT EXISTS release_proposals (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id),
                action TEXT NOT NULL CHECK (action IN ('rollout', 'rollback')),
                percentage INTEGER NOT NULL CHECK (percentage IN (0, 5, 25, 50, 100)),
                safe_flag TEXT NOT NULL,
                target_environment TEXT NOT NULL,
                before_overrides_json TEXT NOT NULL,
                desired_identities_json TEXT NOT NULL,
                source_proposal_id TEXT,
                proposal_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS release_decisions (
                id TEXT PRIMARY KEY,
                release_proposal_id TEXT NOT NULL UNIQUE REFERENCES release_proposals(id),
                decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
                actor TEXT NOT NULL,
                proposal_hash TEXT NOT NULL,
                reason TEXT,
                decided_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS release_receipts (
                id TEXT PRIMARY KEY,
                release_proposal_id TEXT NOT NULL UNIQUE REFERENCES release_proposals(id),
                receipt_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS patch_test_results (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id),
                result_json TEXT NOT NULL,
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

            CREATE INDEX IF NOT EXISTS release_proposals_incident_idx
                ON release_proposals(incident_id, created_at);

            """
        )
        incident_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(incidents)").fetchall()
        }
        if "finding_json" not in incident_columns:
            connection.execute(
                "ALTER TABLE incidents ADD COLUMN finding_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "source_finding_id" not in incident_columns:
            connection.execute("ALTER TABLE incidents ADD COLUMN source_finding_id TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS incidents_source_finding_id_unique "
            "ON incidents(source_finding_id) WHERE source_finding_id IS NOT NULL"
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
