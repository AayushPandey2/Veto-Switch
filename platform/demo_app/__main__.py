"""Run the isolated demonstration app on the local machine only."""

import os

from demo_app.app import create_app


def main() -> None:
    app = create_app()
    host = os.getenv("KILLSWITCH_DEMO_BIND_HOST", "127.0.0.1")
    if host != "127.0.0.1" and not (
        host == "0.0.0.0" and os.getenv("KILLSWITCH_CONTAINERIZED") == "true"
    ):
        raise ValueError("The demo app may bind publicly only inside its isolated container.")
    app.run(host=host, port=5000, debug=False)


if __name__ == "__main__":
    main()
