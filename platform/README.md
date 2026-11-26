# Veto-Switch Platform Demo

This repository includes a local Flask demo app, a FastAPI operator service, and a React containment dashboard. The demo uses synthetic SQLite records and a fixed in-memory file set. Docker Compose publishes its services only on `127.0.0.1`; vulnerable routes are disabled unless both demo safety switches are enabled.

Requires Python 3.11 or newer.

## Start both services with Docker Compose

From the repository root, create `.env` from the example only if you do not already have one, then run:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up --build
```

The dashboard is at `http://127.0.0.1:3000`, the Flask demo is at `http://127.0.0.1:5000`, and the operator API guide is at `http://127.0.0.1:8000/docs`. The backend persists incidents, decisions, operation receipts, and timeline events in a Docker volume, so they survive page refreshes and container restarts. Keep this demo on the local-only Compose setup.

To demonstrate an intentionally vulnerable synthetic example, edit `.env` and set `KILLSWITCH_DEMO_MODE=true`, `KILLSWITCH_ALLOW_VULNERABLE_ROUTES=true`, and the relevant `KILLSWITCH_FLAG_*_V1=true` value. These switches permit only the isolated synthetic demo route; they do not make it suitable for public hosting.

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

## What works now and what still needs setup

- The local dashboard flow supports creating and analyzing synthetic findings, recording an approval or rejection, applying an approved local flag change, verifying the running demo app, viewing the persisted timeline, and exporting a JSON report.
- The local SQLite flag adapter is configured by default. The local approval and verification flow has been run successfully with Docker Compose.
- A Flagsmith management adapter and server-side evaluation path are present, but real Flagsmith changes have **not** been verified. The private `.env` currently needs a dedicated Flagsmith environment key and management token before that path can be used. Never paste those credentials into chat or commit them.
- The stage selector is a preview only: staged percentage targeting is not applied to Flagsmith. The patch action records an advisory event; it does not display a real code diff, run a patch test, or deploy code. Rollback execution is not implemented.
- Production authentication, real cohort telemetry, and the remaining recovery and advisory screens are still future work.

The UI shows the local adapter and labels the environment as local. Treat a green verification result as evidence from the local synthetic demo only, not as proof of a real Flagsmith deployment.

## Run the demo checks

From the repository root, with the virtual environment active:

```powershell
$env:PYTHONPATH = "$PWD\platform"
& .\.venv\Scripts\python.exe -m pytest platform/demo_app/tests -q
```
