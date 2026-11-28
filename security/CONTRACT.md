# Demo app contract (what the security tests need from `platform/demo_app`)

The security lane tests the demo app black-box over HTTP. Until the platform app
exists, `security/stand_in_app/app.py` implements this contract. When the real
app meets it, point `KSX_TARGET_DEMO_URL` at it and the same tests run unchanged.

## Required routes

| Route | Behaviour |
|---|---|
| `GET /health` | `200` JSON: `{"status":"ok","revision":"<sha256>","flags":{"search_v1":bool,"search_v2":bool,"files_v1":bool}, ...}`. `flags` must be **what the app's own evaluation currently returns** (the server-side SDK result, not the management API's value). |
| `GET /search?q=` | `search_v2` on → parameterized implementation. Otherwise `search_v1` on → the planted vulnerable path. Otherwise → safe fallback: `503 {"variant":"search_fallback","status":"search_disabled","results":[]}` with **no DB access**. Results look like `{"variant":..., "results":[{"title":..,"owner":..}]}`. |
| `GET /legacy/search?q=` | Declared alias for the same handler. It must respect the same flags. The registry probes it to catch flag bypasses. |
| `GET /files?name=` | `files_v1` on → the planted traversal path. Off → `503 {"variant":"files_fallback","status":"files_disabled"}`. Missing or invalid file → `4xx`, never `500`. |
| `GET /status`, `GET /catalog` | Unrelated healthy routes for the smoke tests (`/catalog` returns the 3 seeded items). |

Every response carries an `X-KSX-Variant` header naming the code path that served it (`search_v1`, `search_v2`, `search_fallback`, `files_v1`, `files_fallback`, `status`, ...). The verifier uses it as the observed evidence of which path ran.

## Seed data

Seed from `security/fixtures/seed_spec.json` using `default_nonce` (`0000demo`):

- Public documents, plus private rows (`is_private = 1`) whose titles begin with `KSX-CANARY-PRIVATE-`. A private title showing up in a `/search` response is the SQLi oracle.
- The document root holds the `public_files`. The sentinel file `ksx_sentinel.txt` sits **one directory above** the document root, with content beginning `KSX-SENTINEL-OUTSIDE-ROOT-`. Its content showing up in a `/files` response is the traversal oracle.
- `security.seed.build(dir, nonce="0000demo")` creates exactly this layout (SQLite DB, `docs/`, sentinel, `flags.json`). You can call it from the platform seed script.

## Revision

`revision` = `security.revision.tree_revision(<app source dir>)`: sha256 over the top-level `*.py`, `*.txt` and `Dockerfile` files (CRLF normalized). The patch runner refuses to trust a result unless the requested, computed and reported revisions all match.

## Network

Bind the vulnerable app to `127.0.0.1` or to a private compose network only. Allowed hosts are `127.0.0.1`, `localhost`, `::1`, and the compose service names `demo-app` and `patch-target`. They must resolve to loopback or private addresses.
