"""Configuration for the isolated Veto-Switch demonstration app."""

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
except ImportError:  # The local SQLite demo also runs without optional .env loading.
    def load_dotenv(*, override: bool = False) -> bool:
        return False

PLATFORM_ROOT = Path(__file__).resolve().parents[1]


def _read_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    normalized = value.strip().lower()

    if normalized in {"1", "true", "yes"}:
        return True

    if normalized in {"0", "false", "no"}:
        return False

    raise ValueError(f"{name} must be a boolean value.")


@dataclass(frozen=True, slots=True)
class DemoSettings:
    environment: str
    demo_mode: bool
    allow_vulnerable_routes: bool
    database_path: Path
    flag_adapter: str = "local"
    flagsmith_environment_key: str | None = None
    flagsmith_management_token: str | None = None
    flagsmith_api_url: str = "https://api.flagsmith.com/api/v1"

    def __post_init__(self) -> None:
        """Enforce local-only demo safety even for directly constructed settings."""
        if self.environment not in {"local", "test"}:
            raise ValueError("Only local and test environments are supported.")

        if self.allow_vulnerable_routes and not self.demo_mode:
            raise ValueError("Vulnerable routes require explicit demo mode.")

        if self.flag_adapter not in {"local", "flagsmith"}:
            raise ValueError("KILLSWITCH_FLAG_ADAPTER must be local or flagsmith.")

        if self.flag_adapter == "flagsmith":
            if not self.flagsmith_environment_key:
                raise ValueError(
                    "Flagsmith mode requires a server-side environment key."
                )
            parsed_url = urlparse(self.flagsmith_api_url)
            if parsed_url.scheme != "https" or not parsed_url.netloc:
                raise ValueError("The Flagsmith API URL must use HTTPS.")

    @classmethod
    def from_env(cls) -> "DemoSettings":
        # Local runs can load private credentials from an ignored .env file.
        # Existing process variables (including Docker configuration) win.
        load_dotenv(override=False)
        environment = os.getenv("KILLSWITCH_DEMO_ENV", "local").strip().lower()
        demo_mode = _read_bool("KILLSWITCH_DEMO_MODE")
        allow_vulnerable_routes = _read_bool(
            "KILLSWITCH_ALLOW_VULNERABLE_ROUTES"
        )

        database_path = Path(
            os.getenv(
                "KILLSWITCH_DEMO_DATABASE",
                str(PLATFORM_ROOT / "artifacts" / "demo.sqlite3"),
            )
        )

        flag_adapter = os.getenv("KILLSWITCH_FLAG_ADAPTER", "local").strip().lower()
        flagsmith_environment_key = os.getenv(
            "KILLSWITCH_PLATFORM_FLAGSMITH_ENVIRONMENT_KEY"
        )
        flagsmith_management_token = os.getenv(
            "KILLSWITCH_PLATFORM_FLAGSMITH_MANAGEMENT_TOKEN"
        )
        flagsmith_api_url = os.getenv(
            "KILLSWITCH_PLATFORM_FLAGSMITH_API_URL",
            "https://api.flagsmith.com/api/v1",
        ).rstrip("/")

        return cls(
            environment=environment,
            demo_mode=demo_mode,
            allow_vulnerable_routes=allow_vulnerable_routes,
            database_path=database_path,
            flag_adapter=flag_adapter,
            flagsmith_environment_key=flagsmith_environment_key,
            flagsmith_management_token=flagsmith_management_token,
            flagsmith_api_url=flagsmith_api_url,
        )
