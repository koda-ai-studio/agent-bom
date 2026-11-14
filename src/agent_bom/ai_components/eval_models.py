"""Eval-suite models: a detected eval harness, what it targets and what it recorded.

An ``EvalSuite`` is read from a project's files (a promptfoo config, a deepeval
test, an Inspect task, ...). Nothing is executed. ``purpose`` is ``safety``
only when the file shows safety or red-team coverage (red-team plugins, safety
metrics, a known safety benchmark), ``quality`` only when it shows quality
checks, and ``unknown`` otherwise; it is never guessed from names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from agent_bom.finding import stable_id

HARNESSES: tuple[str, ...] = ("promptfoo", "deepeval", "ragas", "inspect", "openai-evals", "langsmith")
PURPOSE_SAFETY = "safety"
PURPOSE_QUALITY = "quality"
PURPOSE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class EvalTarget:
    """The system an eval suite runs against, as its file declares it.

    ``kind`` is ``agent`` (a code entry point such as a promptfoo ``file://``
    provider or the callable a test evaluates), ``model`` (a model id) or
    ``endpoint`` (an HTTP target that cannot be tied to source). ``agent_ids``
    holds the framework agents the reference resolves to; empty means it did
    not resolve and ``unresolved_reason`` says why.
    """

    kind: str
    ref: str
    line_number: int = 0
    evidence: str = ""
    agent_ids: tuple[str, ...] = ()
    unresolved_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ref": self.ref,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "agent_ids": list(self.agent_ids),
            "unresolved_reason": self.unresolved_reason,
        }


@dataclass(frozen=True)
class EvalResult:
    """Results an eval run wrote into the project, labelled with their source file and date."""

    source: str
    source_file: str
    recorded_at: str
    passed: int
    failed: int
    errors: int

    @property
    def pass_rate(self) -> float | None:
        total = self.passed + self.failed + self.errors
        return round(self.passed / total, 4) if total else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_file": self.source_file,
            "recorded_at": self.recorded_at,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "pass_rate": self.pass_rate,
        }


@dataclass(frozen=True)
class EvalSuite:
    """One eval suite detected in project files."""

    harness: str
    name: str
    file_path: str
    line_number: int
    purpose: str = PURPOSE_UNKNOWN
    purpose_evidence: tuple[str, ...] = ()
    targets: tuple[EvalTarget, ...] = ()
    results: tuple[EvalResult, ...] = ()
    scope: str = ""

    @cached_property
    def stable_id(self) -> str:
        return stable_id("eval_suite", self.harness, self.name, self.file_path, str(self.line_number), self.scope)

    @property
    def linked_agent_ids(self) -> list[str]:
        return sorted({agent_id for target in self.targets for agent_id in target.agent_ids})

    @property
    def linked_models(self) -> list[str]:
        return sorted({target.ref for target in self.targets if target.kind == "model" and target.ref})

    @property
    def link_status(self) -> str:
        return "linked" if self.linked_agent_ids or self.linked_models else "unlinked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "stable_id": self.stable_id,
            "kind": "eval_suite",
            "harness": self.harness,
            "name": self.name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "purpose": self.purpose,
            "purpose_evidence": list(self.purpose_evidence),
            "targets": [target.to_dict() for target in self.targets],
            "link_status": self.link_status,
            "linked_agent_ids": self.linked_agent_ids,
            "linked_models": self.linked_models,
            "results": [result.to_dict() for result in self.results],
            "scope": self.scope,
            "provenance": {"source": "eval-scan", "method": "static-read", "executed": False},
        }


@dataclass
class EvalScanResult:
    """Suites found plus what was searched, so a missing eval is never over-claimed."""

    suites: list[EvalSuite] = field(default_factory=list)
    files_examined: int = 0
    scopes: list[str] = field(default_factory=list)
    partial_reason: str = ""
    unreadable: list[str] = field(default_factory=list)

    @property
    def coverage(self) -> dict[str, Any]:
        return {
            "status": "partial" if self.partial_reason else "complete",
            "detail": self.partial_reason,
            "files_examined": self.files_examined,
            "scopes": list(self.scopes),
            "harnesses": list(HARNESSES),
            "unreadable_files": list(self.unreadable[:50]),
        }

    def to_dict(self) -> dict[str, Any]:
        return {"suites": [suite.to_dict() for suite in self.suites], "coverage": self.coverage}
