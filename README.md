# Veto-Switch

## Standalone platform demo

The platform demo runs the synthetic Flask app, operator API, and React dashboard on your machine. If you do not already have a `.env` file, copy `.env.example` to `.env`. Then start the services from the repository root:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up --build
```

Open the dashboard at `http://127.0.0.1:3000`, the demo app at `http://127.0.0.1:5000`, and the API guide at `http://127.0.0.1:8000/docs`. The local API passphrase is in `.env`. All ports are bound to `127.0.0.1`; the demo uses synthetic data. For detailed setup and Flagsmith configuration, see [platform/README.md](platform/README.md).
