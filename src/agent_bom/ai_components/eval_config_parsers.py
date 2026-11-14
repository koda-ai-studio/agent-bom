"""Config-file eval harnesses: promptfoo configs and OpenAI evals registry entries.

Files are parsed with ``yaml.safe_load`` and never run. Formats follow the
harnesses' documented layouts: promptfoo's ``providers``/``targets``,
``redteam`` (``plugins``, ``strategies``), test ``assert`` types and
``outputPath`` result files (EvaluateSummary ``stats`` and ``timestamp``); the
OpenAI evals registry's ``<name>: {id: ...}`` plus ``<id>: {class: ...}`` pairs.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import yaml

from agent_bom.ai_components.eval_linking import AgentIndex, resolve_entry_file, resolve_module_file
from agent_bom.ai_components.eval_models import (
    PURPOSE_QUALITY,
    PURPOSE_SAFETY,
    PURPOSE_UNKNOWN,
    EvalResult,
    EvalSuite,
    EvalTarget,
)
from agent_bom.ast.source_reader import parse_python_source

PROMPTFOO_FILENAMES = frozenset({"promptfooconfig.yaml", "promptfooconfig.yml", "promptfooconfig.json", "redteam.yaml", "redteam.yml"})
# promptfoo assertion types whose pass condition is a safety property.
_PROMPTFOO_SAFETY_ASSERTS = frozenset({"moderation", "is-refusal", "guardrails"})
_ENTRY_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts")
_ENDPOINT_PREFIXES = ("http://", "https://", "ws://", "wss://")
_ENDPOINT_IDS = frozenset({"http", "https", "websocket"})
_MAX_RESULT_BYTES = 8 * 1024 * 1024


class ConfigReadError(ValueError):
    """A candidate config that could not be parsed."""


def load_structured(text: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigReadError(str(exc)) from exc


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle and needle in line:
            return number
    return 1


def _provider_ids(raw: Any) -> list[str]:
    items = raw if isinstance(raw, list) else [raw] if raw is not None else []
    ids: list[str] = []
    for item in items:
        if isinstance(item, str):
            ids.append(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            ids.append(item["id"])
        elif isinstance(item, dict) and len(item) == 1 and isinstance(next(iter(item)), str):
            ids.append(next(iter(item)))
    return [value.strip() for value in ids if value.strip()]


def _imported_agent_ids(root: Path, entry: str, index: AgentIndex) -> list[str]:
    """Agents a thin provider file imports from the project's own modules (one hop)."""
    path = root / entry
    try:
        tree = parse_python_source(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (OSError, SyntaxError, ValueError):
        return []
    ids: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            module_file = resolve_module_file(root, path, node.module, node.level)
            if module_file:
                for alias in node.names:
                    ids.update(index.symbol_in_file(root, module_file, alias.name))
    return sorted(ids)


def _entry_target(root: Path, config: Path, ref: str, line: int, index: AgentIndex) -> EvalTarget:
    entry = resolve_entry_file(root, config.parent, ref)
    evidence = f"promptfoo target file://{ref}"
    if entry is None:
        return EvalTarget("agent", ref, line, evidence, (), f"entry file {ref} not found in the project; no framework agent to link")
    ids = index.roots_in_file(entry)
    if not ids and entry.endswith(".py"):
        ids = _imported_agent_ids(root, entry, index)
    if not ids:
        return EvalTarget("agent", entry, line, evidence, (), f"no framework agent is defined in or imported by {entry}")
    return EvalTarget("agent", entry, line, evidence, tuple(ids))


def _promptfoo_target(root: Path, config: Path, text: str, provider_id: str, index: AgentIndex) -> EvalTarget:
    line = _line_of(text, provider_id)
    lowered = provider_id.lower()
    for prefix in ("file://", "python:"):
        if lowered.startswith(prefix):
            rest = provider_id[len(prefix) :]
            head, sep, tail = rest.rpartition(":")
            entry_path = head if sep and head and tail.isidentifier() else rest
            if entry_path.lower().endswith(_ENTRY_SUFFIXES):
                return _entry_target(root, config, rest, line, index)
    if lowered.startswith(_ENDPOINT_PREFIXES) or lowered in _ENDPOINT_IDS or lowered.startswith(("exec:", "file://", "python:")):
        return EvalTarget("endpoint", provider_id, line, "promptfoo target", (), "endpoint or command target cannot be tied to source")
    if ":" in provider_id:
        return EvalTarget("model", provider_id, line, "promptfoo provider")
    return EvalTarget("endpoint", provider_id, line, "promptfoo provider", (), "provider id names no model or entry file")


def _assert_types(data: dict[str, Any]) -> set[str]:
    blocks: list[Any] = []
    default = data.get("defaultTest")
    if isinstance(default, dict):
        blocks.append(default.get("assert"))
    tests = data.get("tests")
    for test in tests if isinstance(tests, list) else []:
        if isinstance(test, dict):
            blocks.append(test.get("assert"))
    types: set[str] = set()
    for block in blocks:
        for item in block if isinstance(block, list) else []:
            if isinstance(item, dict) and isinstance(item.get("type"), str):
                types.add(item["type"].removeprefix("not-"))
    return types


def _promptfoo_purpose(data: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    redteam = data.get("redteam")
    if isinstance(redteam, dict) or redteam is True:
        block = redteam if isinstance(redteam, dict) else {}
        plugins = [p if isinstance(p, str) else p.get("id") for p in block.get("plugins") or [] if isinstance(p, (str, dict))]
        strategies = [s if isinstance(s, str) else s.get("id") for s in block.get("strategies") or [] if isinstance(s, (str, dict))]
        evidence = ["promptfoo redteam section"]
        if plugins:
            evidence.append("redteam plugins: " + ", ".join(sorted(str(p) for p in plugins if p)))
        if strategies:
            evidence.append("redteam strategies: " + ", ".join(sorted(str(s) for s in strategies if s)))
        return PURPOSE_SAFETY, tuple(evidence)
    types = _assert_types(data)
    safety = sorted(types & _PROMPTFOO_SAFETY_ASSERTS)
    if safety:
        return PURPOSE_SAFETY, ("safety assertion types: " + ", ".join(safety),)
    if types:
        return PURPOSE_QUALITY, ("assertion types: " + ", ".join(sorted(types)),)
    return PURPOSE_UNKNOWN, ()


def promptfoo_results(root: Path, config: Path, output_path: Any) -> list[EvalResult]:
    """Result summaries a promptfoo run wrote to its configured JSON ``outputPath``."""
    paths = output_path if isinstance(output_path, list) else [output_path]
    results: list[EvalResult] = []
    for raw in paths:
        if not isinstance(raw, str) or not raw.lower().endswith(".json"):
            continue
        path = (config.parent / raw).resolve()
        try:
            rel = path.relative_to(root.resolve()).as_posix()
            if not path.is_file() or path.stat().st_size > _MAX_RESULT_BYTES:
                continue
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        nested = data.get("results")
        summary: dict[str, Any] = nested if isinstance(nested, dict) else data
        stats = summary.get("stats") if isinstance(summary.get("stats"), dict) else data.get("stats")
        if not isinstance(stats, dict):
            continue
        counts = [stats.get(key) for key in ("successes", "failures", "errors")]
        if not all(isinstance(value, int) or value is None for value in counts):
            continue
        recorded = summary.get("timestamp") or data.get("timestamp") or data.get("createdAt") or ""
        passed, failed, errors = (int(value or 0) for value in counts)
        results.append(EvalResult("promptfoo output file", rel, str(recorded), passed, failed, errors))
    return results


def parse_promptfoo(root: Path, path: Path, text: str, index: AgentIndex, scope: str) -> list[EvalSuite]:
    data = load_structured(text)
    if not isinstance(data, dict):
        return []
    providers = data.get("targets") if data.get("targets") is not None else data.get("providers")
    if providers is None and "redteam" not in data:
        return []
    targets = tuple(_promptfoo_target(root, path, text, provider_id, index) for provider_id in _provider_ids(providers))
    purpose, evidence = _promptfoo_purpose(data)
    rel = path.relative_to(root).as_posix()
    description = data.get("description")
    name = description.strip() if isinstance(description, str) and description.strip() else rel
    return [
        EvalSuite(
            harness="promptfoo",
            name=name[:200],
            file_path=rel,
            line_number=1,
            purpose=purpose,
            purpose_evidence=evidence,
            targets=targets,
            results=tuple(promptfoo_results(root, path, data.get("outputPath"))),
            scope=scope,
        )
    ]


def is_openai_evals_registry(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    return path.suffix.lower() in {".yaml", ".yml"} and any(parts[i : i + 2] == ["registry", "evals"] for i in range(len(parts) - 1))


def parse_openai_evals_registry(root: Path, path: Path, text: str, scope: str) -> list[EvalSuite]:
    data = load_structured(text)
    if not isinstance(data, dict):
        return []
    suites: list[EvalSuite] = []
    rel = path.relative_to(root).as_posix()
    for name, spec in data.items():
        if not isinstance(name, str) or not isinstance(spec, dict) or not isinstance(spec.get("id"), str):
            continue
        impl = data.get(spec["id"])
        cls = impl.get("class") if isinstance(impl, dict) else None
        if not isinstance(cls, str):
            continue
        evidence: tuple[str, ...] = ()
        purpose = PURPOSE_UNKNOWN
        if cls.startswith("evals.elsuite.basic."):
            purpose, evidence = PURPOSE_QUALITY, (f"OpenAI evals basic check class {cls}",)
        suites.append(
            EvalSuite(
                harness="openai-evals",
                name=name[:200],
                file_path=rel,
                line_number=_line_of(text, f"{name}:"),
                purpose=purpose,
                purpose_evidence=evidence,
                scope=scope,
            )
        )
    return suites
