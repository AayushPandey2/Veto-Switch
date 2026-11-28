"""Build the fake fixture environment (SQLite DB, document root, sentinel file).

DEMO / SYNTHETIC DATA. Owned launches get a fresh random nonce so a canary or
sentinel seen in a response can only have come from this run's fixture.
External targets (the platform's demo app) are seeded with the spec's
`default_nonce`, and the oracles then match on the fixed prefix.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path

SPEC_PATH = Path(__file__).resolve().parent / "fixtures" / "seed_spec.json"


def load_spec() -> dict:
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


@dataclass
class FixtureEnv:
    base_dir: Path
    db_path: Path
    doc_root: Path
    sentinel_path: Path
    flags_file: Path
    nonce: str
    canaries: list[str]
    sentinel_token: str

    def env(self) -> dict[str, str]:
        return {"KSX_DB": str(self.db_path), "KSX_DOC_ROOT": str(self.doc_root),
                "KSX_FLAGS_FILE": str(self.flags_file)}

    def set_flags(self, **flags: bool) -> None:
        current = json.loads(self.flags_file.read_text(encoding="utf-8"))
        current.update(flags)
        self.flags_file.write_text(json.dumps(current), encoding="utf-8")


def build(base_dir: str | Path, *, nonce: str | None = None, flags: dict | None = None) -> FixtureEnv:
    spec = load_spec()
    nonce = nonce or secrets.token_hex(6)
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)

    db_path = base / "demo.sqlite3"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.executescript(
        "CREATE TABLE documents (id INTEGER PRIMARY KEY, title TEXT NOT NULL, owner TEXT NOT NULL,"
        " is_private INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE catalog (sku TEXT PRIMARY KEY, name TEXT NOT NULL);"
    )
    for d in spec["public_documents"]:
        conn.execute("INSERT INTO documents (title, owner, is_private) VALUES (?, ?, 0)", (d["title"], d["owner"]))
    canaries = []
    for d in spec["private_documents"]:
        title = d["title"].format(nonce=nonce)
        canaries.append(title)
        conn.execute("INSERT INTO documents (title, owner, is_private) VALUES (?, ?, 1)", (title, d["owner"]))
    for item in spec["catalog"]:
        conn.execute("INSERT INTO catalog (sku, name) VALUES (?, ?)", (item["sku"], item["name"]))
    conn.commit()
    conn.close()

    # <base>/ksx_sentinel.txt sits one level above the document root <base>/docs.
    doc_root = base / "docs"
    doc_root.mkdir(exist_ok=True)
    for name, content in spec["public_files"].items():
        (doc_root / name).write_text(content, encoding="utf-8")
    sentinel_token = spec["sentinel"]["content_template"].format(nonce=nonce)
    sentinel_path = base / spec["sentinel"]["filename"]
    sentinel_path.write_text(sentinel_token, encoding="utf-8")

    flags_file = base / "flags.json"
    flags_file.write_text(json.dumps(flags or {"search_v1": True, "search_v2": False, "files_v1": True}),
                          encoding="utf-8")
    return FixtureEnv(base, db_path, doc_root, sentinel_path, flags_file, nonce, canaries, sentinel_token)
