"""Run the standalone local API on loopback only."""

import os

import uvicorn

from backend.app import create_app


def main() -> None:
    host = os.getenv("KILLSWITCH_BACKEND_BIND_HOST", "127.0.0.1")
    if host != "127.0.0.1" and not (
        host == "0.0.0.0" and os.getenv("KILLSWITCH_CONTAINERIZED") == "true"
    ):
        raise ValueError("The API may bind publicly only inside its isolated container.")
    uvicorn.run(create_app(), host=host, port=8000)


if __name__ == "__main__":
    main()
