# Veto-Switch

## Standalone platform demo

The platform demo runs a synthetic Flask app, an authenticated operator API, and the React dashboard on your machine. If you do not already have a `.env` file, copy `.env.example` to `.env`. Then start the services from the repository root:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up --build
```

Open the dashboard at `http://127.0.0.1:3000`, the demo app at `http://127.0.0.1:5000`, and the API guide at `http://127.0.0.1:8000/docs`. All ports are bound to `127.0.0.1`; only synthetic data is used. The local dashboard flow now includes normalized finding intake, human-approved containment, post-change checks, patch tests, separately approved identity stages and rollback proposals, event history, telemetry, and evidence export. For setup, safety limits, Flagsmith configuration, and smoke-check instructions, see [platform/README.md](platform/README.md).
