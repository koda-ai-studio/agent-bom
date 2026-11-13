"""Model references keep the full vendor model ID.

IDs follow the vendors' published formats (Anthropic models overview, OpenAI
models page, Gemini models page). A pattern that stopped at ``claude-sonnet-4``
inside ``claude-sonnet-4-5`` or at ``gpt-4`` inside ``gpt-4.1`` reported a
different model than the code calls.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.ai_components import scan_source
from agent_bom.ai_components.models import AIComponentType


def _models(tmp_path: Path, text: str) -> list[str]:
    (tmp_path / "app.py").write_text(text)
    report = scan_source(str(tmp_path))
    return sorted(c.name for c in report.components if c.component_type == AIComponentType.MODEL_REFERENCE)


@pytest.mark.parametrize(
    "model_id",
    [
        # Anthropic
        "claude-sonnet-4-5",
        "claude-sonnet-4-5-20250929",
        "claude-opus-4-1-20250805",
        "claude-opus-4-20250514",
        "claude-haiku-4-5-20251001",
        "claude-opus-4-6",
        "claude-opus-5",
        "claude-opus-5-5",
        "claude-sonnet-5",
        "claude-sonnet-5-5",
        "claude-haiku-5-5",
        "claude-fable-5-2",
        "claude-mythos-5-2",
        "claude-3-7-sonnet-20250219",
        "claude-3-5-haiku-latest",
        "claude-3-opus-20240229",
        # OpenAI
        "gpt-4.1",
        "gpt-4.1-mini",
        "gpt-4.1-2025-04-14",
        "gpt-4o",
        "gpt-4o-mini-2024-07-18",
        "gpt-4-turbo",
        "gpt-5",
        "gpt-5-mini",
        "gpt-5-2025-08-07",
        "gpt-5.1-codex-mini",
        "gpt-6.1-sol",
        "gpt-oss-120b",
        "o1",
        "o1-mini",
        "o3",
        "o3-pro",
        "o3-2025-04-16",
        "o4-mini",
        "o4-mini-deep-research",
        # Google
        "gemini-2.5-pro",
        "gemini-2.5-flash-lite",
        "gemini-3-flash-preview",
        "gemini-3.1-pro-preview",
        "gemini-2.5-flash-native-audio-preview-12-2025",
        "gemini-1.5-pro-002",
    ],
)
def test_full_model_id_is_reported(tmp_path: Path, model_id: str) -> None:
    assert _models(tmp_path, f'client.create(model="{model_id}")\n') == [model_id]


@pytest.mark.parametrize(
    "text, expected",
    [
        ('m = "claude-sonnet-4-5"', ["claude-sonnet-4-5"]),
        ('m = "claude-opus-4.1"', ["claude-opus-4.1"]),
        ('m = "gpt-4.1"', ["gpt-4.1"]),
        ('m = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"', ["claude-sonnet-4-5-20250929"]),
        ('m = "openai/gpt-5"', ["gpt-5"]),
        ("o1 = build()\nfoo-o3 = 1\n", []),
        ('m = "gpt-3.5-turbo"', []),
    ],
    ids=["dash-minor", "dot-minor", "dot-version", "bedrock", "router-prefix", "bare-o-identifiers", "deprecated-only"],
)
def test_boundaries(tmp_path: Path, text: str, expected: list[str]) -> None:
    assert _models(tmp_path, text + "\n") == expected


@pytest.mark.parametrize("model_id", ["glm-4.5", "glm-4.6-air", "deepseek-v3.1", "qwen2.5-72b-instruct", "mistral-large-2411"])
def test_other_families_keep_point_versions(tmp_path: Path, model_id: str) -> None:
    assert _models(tmp_path, f'm = "{model_id}"\n') == [model_id]


@pytest.mark.parametrize("model_id", ["gpt-3.5-turbo", "gpt-3.5-turbo-0125", "gpt-3.5-turbo-16k"])
def test_deprecated_ids_are_reported_whole(tmp_path: Path, model_id: str) -> None:
    (tmp_path / "app.py").write_text(f'm = "{model_id}"\n')
    report = scan_source(str(tmp_path))
    assert [c.name for c in report.components if c.component_type == AIComponentType.DEPRECATED_MODEL] == [model_id]
