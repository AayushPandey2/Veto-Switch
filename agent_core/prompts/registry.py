"""Centralized versioned prompt registry with SHA-256 content integrity hashing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field
from shared.enums import AITaskType
from shared.exceptions import ConfigurationError
from shared.schemas import KillswitchModel
from shared.serialization import sha256_text

_DEFAULT_PROMPTS_DIR = Path(__file__).resolve().parent


class PromptMetadata(KillswitchModel):
    """Metadata and traceable content hash for a registered prompt version."""

    prompt_id: str = Field(min_length=1)
    task_type: AITaskType
    version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    system_file: str = Field(min_length=1)
    task_file: str = Field(min_length=1)
    repair_file: str = Field(min_length=1)
    examples_file: str | None = None
    input_requirements: list[str] = Field(default_factory=list)
    expected_response_schema: str = Field(min_length=1)
    supported_capabilities: list[str] = Field(default_factory=list)
    created_at: str = Field(min_length=1)
    revision_notes: str = Field(default="")
    evaluation_case_ids: list[str] = Field(default_factory=list)
    content_hash: str = Field(min_length=64, max_length=64)


class LoadedPrompt(KillswitchModel):
    """Loaded prompt templates keeping system instructions separate from untrusted data."""

    metadata: PromptMetadata
    system_instructions: str = Field(min_length=1)
    task_template: str = Field(min_length=1)
    repair_template: str = Field(min_length=1)
    examples: list[dict[str, Any]] = Field(default_factory=list)

    def render_user_message(self, *, context_json: str) -> str:
        """Render the bounded user/task message without touching ``system_instructions``."""
        return self.task_template.replace("{context_json}", context_json)

    def render_repair_message(self, *, validation_errors: str, context_json: str) -> str:
        """Render a bounded repair prompt carrying only sanitized validation errors."""
        rendered = self.repair_template.replace("{validation_errors}", validation_errors)
        return rendered.replace("{context_json}", context_json)


class PromptRegistry:
    """Loads versioned prompt templates from ``agent_core/prompts/versions.json``."""

    def __init__(self, prompts_dir: Path | str = _DEFAULT_PROMPTS_DIR) -> None:
        self._root = Path(prompts_dir)
        self._versions_path = self._root / "versions.json"
        if not self._versions_path.exists():
            raise ConfigurationError(
                f"Prompt versions manifest missing at {self._versions_path}."
            )
        self._entries: dict[tuple[AITaskType, str], LoadedPrompt] = {}
        self._defaults: dict[AITaskType, str] = {}
        self._load_all()

    def _read_template(self, relative_path: str) -> str:
        full_path = (self._root / relative_path).resolve()
        if not full_path.is_relative_to(self._root.resolve()):
            raise ConfigurationError(
                f"Prompt file path escapes prompts directory: {relative_path!r}."
            )
        if not full_path.exists():
            raise ConfigurationError(f"Prompt template missing: {full_path}")
        return full_path.read_text(encoding="utf-8")

    def _load_all(self) -> None:
        raw = json.loads(self._versions_path.read_text(encoding="utf-8"))
        for item in raw.get("prompts", []):
            sys_txt = self._read_template(item["system_file"])
            task_txt = self._read_template(item["task_file"])
            repair_txt = self._read_template(item["repair_file"])
            examples_list: list[dict[str, Any]] = []
            examples_raw_txt = ""
            if item.get("examples_file"):
                examples_raw_txt = self._read_template(item["examples_file"])
                ex_json = json.loads(examples_raw_txt)
                if isinstance(ex_json, dict) and isinstance(ex_json.get("examples"), list):
                    examples_list = list(ex_json["examples"])

            combined = "\n---\n".join([sys_txt, task_txt, repair_txt, examples_raw_txt])
            content_hash = sha256_text(combined)
            meta = PromptMetadata(
                prompt_id=item["prompt_id"],
                task_type=AITaskType(item["task_type"]),
                version=item["version"],
                description=item["description"],
                system_file=item["system_file"],
                task_file=item["task_file"],
                repair_file=item["repair_file"],
                examples_file=item.get("examples_file"),
                input_requirements=item.get("input_requirements", []),
                expected_response_schema=item["expected_response_schema"],
                supported_capabilities=item.get("supported_capabilities", []),
                created_at=item["created_at"],
                revision_notes=item.get("revision_notes", ""),
                evaluation_case_ids=item.get("evaluation_case_ids", []),
                content_hash=content_hash,
            )
            loaded = LoadedPrompt(
                metadata=meta,
                system_instructions=sys_txt,
                task_template=task_txt,
                repair_template=repair_txt,
                examples=examples_list,
            )
            self._entries[(meta.task_type, meta.version)] = loaded
            if meta.task_type not in self._defaults:
                self._defaults[meta.task_type] = meta.version

    def get_prompt(
        self, task_type: AITaskType, *, version: str | None = None
    ) -> LoadedPrompt:
        """Retrieve a versioned prompt by ``task_type`` and optional ``version``."""
        target_version = version or self._defaults.get(task_type)
        if not target_version:
            raise ConfigurationError(f"No default prompt configured for task {task_type.value!r}.")
        loaded = self._entries.get((task_type, target_version))
        if loaded is None:
            raise ConfigurationError(
                f"Prompt version {target_version!r} not found for task {task_type.value!r}.",
                context={"task_type": task_type.value, "version": target_version},
            )
        return loaded

    def list_prompts(self, task_type: AITaskType | None = None) -> list[PromptMetadata]:
        """List registered prompt metadata entries."""
        items = [lp.metadata for lp in self._entries.values()]
        if task_type is not None:
            items = [m for m in items if m.task_type == task_type]
        return items
