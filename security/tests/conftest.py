from __future__ import annotations

import itertools
from contextlib import ExitStack
from dataclasses import dataclass

import pytest

from security import sandbox, seed
from security.evidence import ArtifactStore
from security.probes import OracleContext

SOURCE_DIR = sandbox.SOURCES["stand_in"]["source_dir"]
_counter = itertools.count()


@dataclass
class Target:
    target_id: str
    fixture: seed.FixtureEnv
    ctx: OracleContext


@pytest.fixture
def store(tmp_path) -> ArtifactStore:
    return ArtifactStore(tmp_path / "artifacts")


@pytest.fixture
def local_sandbox(monkeypatch):
    monkeypatch.setenv("KSX_ALLOW_LOCAL_SANDBOX", "1")


@pytest.fixture
def make_target(tmp_path, local_sandbox):
    """Launch the stand-in demo target as a local subprocess on a free loopback port."""
    stack = ExitStack()

    def _make(flags: dict | None = None, **extra_env) -> Target:
        fx = seed.build(tmp_path / f"fx-{next(_counter)}", flags=flags)
        target_id, logs = stack.enter_context(
            sandbox.launch(SOURCE_DIR, fx, mode="local", extra_env={k: str(v) for k, v in extra_env.items()}))
        assert logs["healthy"], logs
        return Target(target_id, fx, sandbox.oracle_for(fx, "local"))

    yield _make
    stack.close()


@pytest.fixture
def target(make_target) -> Target:
    return make_target()
