"""Configuration for the isolated Veto-Switch demonstration app."""

import os
from dataclasses import dataclass
from pathlib import Path

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

    def __post_init__(self) -> None:
        """Enforce local-only demo safety even for directly constructed settings."""
        if self.environment not in {"local", "test"}:
            raise ValueError("Only local and test environments are supported.")

        if self.allow_vulnerable_routes and not self.demo_mode:
            raise ValueError("Vulnerable routes require explicit demo mode.")

    @classmethod
    def from_env(cls) -> "DemoSettings":
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

        return cls(
            environment=environment,
            demo_mode=demo_mode,
            allow_vulnerable_routes=allow_vulnerable_routes,
            database_path=database_path,
        )
