# Standalone Platform Demo

A local Flask app for demonstrating safe and intentionally vulnerable search and file routes. It uses synthetic SQLite records and a fixed in-memory file set. Vulnerable routes are disabled by default and the app binds only to `127.0.0.1`.

Requires Python 3.11 or newer.

## Start both services with Docker Compose

From the repository root, copy `.env.example` to `.env` once, then run:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

The Flask demo is at `http://127.0.0.1:5000`; the operator API and its interactive guide are at `http://127.0.0.1:8000/docs`. Both ports are bound to the local machine only. The database is kept in a Docker volume. To show an intentionally vulnerable synthetic example, edit `.env` and set `KILLSWITCH_DEMO_MODE=true`, `KILLSWITCH_ALLOW_VULNERABLE_ROUTES=true`, and the scenario's `KILLSWITCH_FLAG_*_V1=true` value. Keep the app on the local-only Compose setup.

## Start on Windows PowerShell

From the repository root:

```powershell
python -m venv .venv
$venvPython = ".\.venv\Scripts\python.exe"
& $venvPython -m pip install -r platform/requirements.txt
$env:PYTHONPATH = "$PWD\platform"
& $venvPython -m demo_app
```

Open `http://127.0.0.1:5000/health`. Normal search is available at `/search?q=demo_user_01`; the public synthetic file is available at `/files?path=readme.txt`. Route and feature-flag metadata is at `/manifest`.

## Show the local security demos

In the same PowerShell window, set these before starting the app:

```powershell
$env:KILLSWITCH_DEMO_MODE = "true"
$env:KILLSWITCH_ALLOW_VULNERABLE_ROUTES = "true"
$env:KILLSWITCH_FLAG_SEARCH_V1 = "true"
$env:KILLSWITCH_FLAG_FILES_V1 = "true"
$env:PYTHONPATH = "$PWD\platform"
& .\.venv\Scripts\python.exe -m demo_app
```

Use a second PowerShell window to send a local path traversal example:

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/demo/files-v1?path=..%2Fprivate%2Finternal_note.txt'
```

The vulnerable examples use only synthetic records. The path traversal example can reveal a fake private note from the in-memory demo set; it never reads arbitrary files from disk. Set `KILLSWITCH_FLAG_SEARCH_V2=true` or `KILLSWITCH_FLAG_FILES_V2=true` before starting the app to select the safe version. When the safe version is enabled, it takes precedence and the direct vulnerable demo route is hidden.

## Local approval and verification API

The standalone FastAPI service persists incidents, proposals, decisions, receipts and audit events in the same local SQLite database as the demo app. By default it uses a clearly labeled local SQLite flag adapter. It can use a real Flagsmith environment when `KILLSWITCH_FLAG_ADAPTER=flagsmith` is selected in a private `.env` file.

For a Flagsmith run, first create a dedicated demo environment containing `search_v1`, `search_v2`, `files_v1` and `files_v2`. Copy `.env.example` to `.env`, then fill in the server-side environment key and organization management token there. In PowerShell, run `Copy-Item .env.example .env`, then open `.env` in an editor. Do not send either key in chat or add them to frontend files. Set `KILLSWITCH_FLAG_ADAPTER=flagsmith`. The backend reads the environment state, binds the approval to the observed starting state, and only then updates flags after approval. It reads the state back and records an operation receipt. The Flask app evaluates flags with the Flagsmith server SDK; its intentionally vulnerable routes still require both local demo safety switches.

Run the demo app in one PowerShell window with the local demonstration gates enabled, as shown above. In a second window from the repository root, start the API:

```powershell
$env:PYTHONPATH = "$PWD\platform"
$env:KILLSWITCH_OPERATOR_PASSPHRASE = "local-demo-passphrase"
& .\.venv\Scripts\python.exe -m backend
```

Open `http://127.0.0.1:8000/docs`. Use the `X-Operator-Passphrase` header on write operations. The local flow is: create an incident, analyze it, approve the proposal using the displayed hash, apply it, then verify it against the running Flask app. A verification failure or unreachable demo app is reported as failed/unknown, never as success.

The local SQLite mode is available without Flagsmith credentials. The real Flagsmith mode requires a working account, the four configured flags, network access and a token with permission to update that environment. If the real service cannot be reached or a flag is missing/ambiguous, the API reports an error and does not claim containment.

The React dashboard, Docker Compose, staged targeting/rollout, patch/recovery screens and production authentication remain outstanding roadmap work.

## Run the demo checks

From the repository root, with the virtual environment active:

```powershell
$env:PYTHONPATH = "$PWD\platform"
& .\.venv\Scripts\python.exe -m pytest platform/demo_app/tests -q
```
