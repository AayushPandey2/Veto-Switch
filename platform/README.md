# Standalone Platform Demo

A local Flask app for demonstrating safe and intentionally vulnerable search and file routes. It uses synthetic SQLite records and a fixed in-memory file set. Vulnerable routes are disabled by default and the app binds only to `127.0.0.1`.

Requires Python 3.11 or newer.

## Start on Windows PowerShell

From the repository root:

```powershell
python -m venv .venv
$venvPython = ".\.venv\Scripts\python.exe"
& $venvPython -m pip install -r platform/requirements.txt
$env:PYTHONPATH = "$PWD\platform"
& $venvPython -m demo_app
```

Open `http://127.0.0.1:5000/health`. Normal search is available at `/search?q=demo_user_01`; the public synthetic file is available at `/files?path=readme.txt`.

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

## Run the demo checks

From the repository root, with the virtual environment active:

```powershell
$env:PYTHONPATH = "$PWD\platform"
& .\.venv\Scripts\python.exe -m pytest platform/demo_app/tests -q
```
