"""Stand-in demo target for the security lane.  DEMO / SYNTHETIC DATA ONLY.

This mirrors the contract the platform lane's real demo app must satisfy (see
security/CONTRACT.md) so security tests can run before that app exists. It
contains TWO DELIBERATE VULNERABILITIES (search_v1 SQL injection, files_v1 path
traversal). It binds to 127.0.0.1 by default and must never be exposed publicly.

Flags come from a local JSON file here; the real app evaluates Flagsmith.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, g, jsonify, request

HERE = Path(__file__).resolve().parent
DB_PATH = os.environ.get("KSX_DB", str(HERE / "demo.sqlite3"))
DOC_ROOT = os.environ.get("KSX_DOC_ROOT", str(HERE / "docs"))
FLAGS_FILE = os.environ.get("KSX_FLAGS_FILE", str(HERE / "flags.json"))
FLAG_CACHE_SECONDS = float(os.environ.get("KSX_FLAG_CACHE_SECONDS", "0"))
# Simulated misconfiguration used only by a negative test: the legacy alias
# skips the flag check. Off unless explicitly set.
BUG_ALIAS_BYPASS = os.environ.get("KSX_BUG_ALIAS_BYPASS") == "1"

DEFAULT_FLAGS = {"search_v1": True, "search_v2": False, "files_v1": True}

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)  # its access log includes query strings
log = logging.getLogger("demo_app")


def tree_revision(root: Path) -> str:
    """sha256 over (relative path, file sha256) of the app's source files.

    Same algorithm as security/revision.py so the sandbox can check that the
    code under test is the code it launched.
    """
    h = hashlib.sha256()
    for p in sorted(root.iterdir()):
        if not p.is_file() or not (p.suffix in {".py", ".txt"} or p.name == "Dockerfile"):
            continue
        content = p.read_bytes().replace(b"\r\n", b"\n")
        h.update(p.name.encode() + b"\0")
        h.update(hashlib.sha256(content).hexdigest().encode() + b"\n")
    return h.hexdigest()


REVISION = tree_revision(HERE)
_flag_cache: dict = {"at": 0.0, "flags": None}


def current_flags() -> dict:
    now = time.time()
    if _flag_cache["flags"] is not None and now - _flag_cache["at"] < FLAG_CACHE_SECONDS:
        return _flag_cache["flags"]
    try:
        with open(FLAGS_FILE, encoding="utf-8") as f:
            flags = {**DEFAULT_FLAGS, **json.load(f)}
    except FileNotFoundError:
        flags = dict(DEFAULT_FLAGS)
    _flag_cache.update(at=now, flags=flags)
    return flags


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@app.after_request
def _log_and_tag(resp):
    variant = getattr(g, "variant", "none")
    resp.headers["X-KSX-Variant"] = variant
    resp.headers["X-KSX-Revision"] = REVISION
    # Route, variant and status only: no query strings or bodies.
    log.info("route=%s variant=%s status=%s", request.path, variant, resp.status_code)
    return resp


@app.get("/health")
def health():
    g.variant = "health"
    flags = current_flags()
    return jsonify(status="ok", service="demo-app", revision=REVISION, flags=flags,
                   flags_source="file", flags_age_s=round(time.time() - _flag_cache["at"], 3),
                   synthetic_data=True)


@app.get("/status")
def status():
    g.variant = "status"
    return jsonify(status="ok", route="status", synthetic_data=True)


@app.get("/catalog")
def catalog():
    g.variant = "catalog"
    rows = db().execute("SELECT sku, name FROM catalog ORDER BY sku").fetchall()
    return jsonify(items=[{"sku": s, "name": n} for s, n in rows], synthetic_data=True)


def search_v1(q: str):
    # DELIBERATELY VULNERABLE (demo only): user input concatenated into SQL.
    sql = ("SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE '%"
           + q + "%' ORDER BY title")
    return db().execute(sql).fetchall()


def search_v2(q: str):
    sql = "SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE ? ORDER BY title"
    return db().execute(sql, (f"%{q}%",)).fetchall()


def _search_response(rows, variant):
    g.variant = variant
    return jsonify(variant=variant, results=[{"title": t, "owner": o} for t, o in rows])


def dispatch_search():
    q = request.args.get("q", "")
    flags = current_flags()
    try:
        if flags.get("search_v2"):
            return _search_response(search_v2(q), "search_v2")
        if flags.get("search_v1"):
            return _search_response(search_v1(q), "search_v1")
    except sqlite3.Error:
        return jsonify(error="search_failed"), 500
    g.variant = "search_fallback"
    return jsonify(variant="search_fallback", status="search_disabled", results=[]), 503


@app.get("/search")
def search():
    return dispatch_search()


@app.get("/legacy/search")
def legacy_search():
    if BUG_ALIAS_BYPASS:
        try:
            return _search_response(search_v1(request.args.get("q", "")), "search_v1")
        except sqlite3.Error:
            return jsonify(error="search_failed"), 500
    return dispatch_search()


def files_v1(name: str):
    # DELIBERATELY VULNERABLE (demo only): no normalization or root check.
    path = os.path.join(DOC_ROOT, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


@app.get("/files")
def files():
    name = request.args.get("name", "")
    if not current_flags().get("files_v1"):
        g.variant = "files_fallback"
        return jsonify(variant="files_fallback", status="files_disabled"), 503
    g.variant = "files_v1"
    try:
        return jsonify(variant="files_v1", name=name, content=files_v1(name))
    except (OSError, ValueError):
        return jsonify(variant="files_v1", error="not_found"), 404


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    app.run(host=os.environ.get("KSX_HOST", "127.0.0.1"), port=int(os.environ.get("KSX_PORT", "5001")),
            debug=False, use_reloader=False)
