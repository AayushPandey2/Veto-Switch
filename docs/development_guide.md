# Killswitch X — Development Guide

## 1. Local Environment Setup

Requires **Python 3.11+** (verified on Python 3.12 via `uv`).

```bash
# Create virtual environment
uv venv --python 3.12 .venv

# Install package and development dependencies (pytest, ruff, mypy)
uv pip install --python .venv/bin/python -e ".[dev]"

# Optional environment template for local configuration
cp .env.example .env
```

> [!NOTE]
> All foundational unit tests, contract tests, and fixture validations run completely offline without `.env` or any LLM / Flagsmith credentials.

## 2. Verification Commands

```bash
# Validate config/*.json and shared/fixtures/*.json
.venv/bin/python scripts/validate_fixtures.py

# Run Ruff linter
.venv/bin/ruff check .

# Run strict Mypy type checks on shared/
.venv/bin/mypy shared

# Run all unit and contract tests
.venv/bin/pytest -v
```

## 3. Extending Shared Contracts Safely

### Adding a New Enumeration
1. Add a `StrEnum` class with a clear docstring to `shared/enums.py`.
2. Export it in `shared/__init__.py`.
3. Add unit tests verifying serialized string values and rejection of invalid values.

### Adding a New Shared Schema
1. Subclass `KillswitchModel` in `shared/schemas.py` (inherits `extra="forbid"`, whitespace stripping, assignment validation).
2. Use `IdentifierStr`, `UtcDatetime`, `StrictBool`, `StrictInt`, and explicit `Field(description=...)` documenting numeric units.
3. Add `@model_validator(mode="after")` for fail-closed invariants.
4. Export in `shared/__init__.py` and document in `docs/data_contracts.md`.

### Adding a New Event Type
1. Add the enum member to `EventType` in `shared/enums.py`.
2. If security-sensitive, create a typed payload subclass of `KillswitchModel` in `shared/schemas.py` and register it in `_EVENT_PAYLOAD_MODELS`.
3. Add a timeline test in `tests/unit/test_schemas_core.py`.

### Adding a Fixture
1. Add internally consistent entries under `"valid"` or `"invalid"` in the appropriate `shared/fixtures/*.json` file.
2. Always include explicit `provenance` (`"reference_fixture"` or `"synthetic_telemetry"`).
3. If adding a `ContainmentProposal`, compute its exact `proposal_hash` via `ContainmentProposal.with_computed_hash(...)`.
4. Update `scripts/validate_fixtures.py` and `tests/contract/test_fixtures_validation.py`.

### Updating an Existing Contract Without Breaking Other Engineers
1. Never rename or remove existing fields from `shared/schemas.py` without coordinating across `agent_core`, `remediation`, `security`, and `platform`.
2. Prefer additive optional fields with safe defaults (`None` or `default_factory=...`) that preserve fail-closed semantics.
3. Run `pytest`, `mypy shared`, and `validate_fixtures.py` before opening a PR.
