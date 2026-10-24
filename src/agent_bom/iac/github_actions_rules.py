"""GitHub Actions workflow hardening rules.

Rules
-----
GHA-001  pull_request_target workflow checks out the pull request head (high)
GHA-002  Remote action or reusable workflow not pinned to a full commit SHA (medium)
GHA-003  Untrusted ``${{ github.event.* }}`` expression inside ``run:`` (high)
GHA-004  ``permissions: write-all`` (medium) or no top-level ``permissions:`` (low)

Untrusted contexts follow GitHub's security hardening guide for script
injection: attacker-controlled titles, bodies, messages, branch names and
author fields. Passing them through ``env:`` and quoting the variable is the
documented safe pattern and is not flagged.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from agent_bom.github_actions import _FULL_COMMIT_SHA_RE, _parse_remote_action_reference
from agent_bom.iac.models import IaCFinding
from agent_bom.iac.yaml_lines import key_line, safe_load_with_lines

_UNTRUSTED_EXPRESSION_RE = re.compile(
    r"\$\{\{[^}]*?\b("
    r"github\.head_ref"
    r"|github\.event\.(?:"
    r"issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))"
    r"|(?:comment|review|review_comment)\.body"
    r"|discussion\.(?:title|body)"
    r"|pages\.[^}\s]*?\.page_name"
    r"|commits\.[^}\s]*?\.(?:message|author\.(?:email|name))"
    r"|head_commit\.(?:message|author\.(?:email|name))"
    r"|workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:email|name)))"
    r"))"
)
_PR_HEAD_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/|github\.event\.pull_request\.merge_commit_sha"
)
_BLOCK_SCALAR_RE = re.compile(r":\s*[|>][-+0-9]*\s*(?:#.*)?$")


def is_workflow_file(path: Path) -> bool:
    return path.suffix in {".yml", ".yaml"} and path.parent.name == "workflows" and path.parent.parent.name == ".github"


def _finding(rule_id: str, severity: str, title: str, message: str, rel_path: str, line: int) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=rel_path,
        line_number=line,
        category="github_actions",
        compliance=["NIST-SA-12", "NIST-CM-7"],
    )


def _triggers(document: dict[Any, Any]) -> set[str]:
    # YAML 1.1 loads a bare ``on`` key as boolean True.
    on = document.get("on", document.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, (list, dict)):
        return {str(event) for event in on}
    return set()


def _steps(document: dict[Any, Any]) -> list[tuple[Any, int, dict[Any, Any]]]:
    """``(steps list, index, step)`` for every step of every job."""
    found: list[tuple[Any, int, dict[Any, Any]]] = []
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return found
    for job in jobs.values():
        steps = job.get("steps") if isinstance(job, dict) else None
        if isinstance(steps, list):
            found.extend((steps, index, step) for index, step in enumerate(steps) if isinstance(step, dict))
    return found


def _script_lines(raw_lines: list[str], container: dict[Any, Any], key: str) -> list[tuple[str, int]]:
    """Each line of a ``run``/``script`` scalar with its source line."""
    value = container.get(key)
    line = key_line(container, key)
    if not isinstance(value, str) or not line:
        return []
    header = raw_lines[line - 1] if line <= len(raw_lines) else ""
    if _BLOCK_SCALAR_RE.search(header):
        return [(text, line + 1 + offset) for offset, text in enumerate(value.splitlines())]
    return [(value, line)]


def _pr_head_checkouts(steps: list[tuple[Any, int, dict[Any, Any]]], rel_path: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    for _, _, step in steps:
        uses = str(step.get("uses", ""))
        with_args = step.get("with")
        if not uses.startswith("actions/checkout") or not isinstance(with_args, dict):
            continue
        for key in ("ref", "repository"):
            if _PR_HEAD_REF_RE.search(str(with_args.get(key, ""))) or (
                key == "repository" and "pull_request.head.repo" in str(with_args.get(key, ""))
            ):
                findings.append(
                    _finding(
                        "GHA-001",
                        "high",
                        "pull_request_target checks out untrusted pull request code",
                        "This pull_request_target workflow checks out the pull request head while it holds the base "
                        "repository's secrets and write token. Use pull_request, or never build or run the checked-out code.",
                        rel_path,
                        key_line(with_args, key),
                    )
                )
                break
    return findings


def _unpinned_actions(steps: list[tuple[Any, int, dict[Any, Any]]], document: dict[Any, Any], rel_path: str) -> list[IaCFinding]:
    references: list[tuple[str, int]] = [(str(step.get("uses")), key_line(step, "uses")) for _, _, step in steps if step.get("uses")]
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        references.extend((str(job["uses"]), key_line(job, "uses")) for job in jobs.values() if isinstance(job, dict) and job.get("uses"))
    findings: list[IaCFinding] = []
    for reference, line in references:
        parsed = _parse_remote_action_reference(reference)
        if parsed is None or _FULL_COMMIT_SHA_RE.fullmatch(parsed[2]):
            continue
        findings.append(
            _finding(
                "GHA-002",
                "medium",
                "Action not pinned to a commit SHA",
                f"'{reference}' resolves a mutable tag or branch. Pin remote actions and reusable workflows to a full commit SHA.",
                rel_path,
                line,
            )
        )
    return findings


def _script_injections(steps: list[tuple[Any, int, dict[Any, Any]]], raw_lines: list[str], rel_path: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    for _, _, step in steps:
        scripts = _script_lines(raw_lines, step, "run")
        with_args = step.get("with")
        if str(step.get("uses", "")).startswith("actions/github-script") and isinstance(with_args, dict):
            scripts += _script_lines(raw_lines, with_args, "script")
        for text, line in scripts:
            for match in _UNTRUSTED_EXPRESSION_RE.finditer(text):
                findings.append(
                    _finding(
                        "GHA-003",
                        "high",
                        "Untrusted input interpolated into a script",
                        f"'{match.group(1)}' is attacker-controlled and is expanded into the script before it runs "
                        "(script injection). Pass it through env: and reference the quoted variable instead.",
                        rel_path,
                        line,
                    )
                )
    return findings


def _permissions(document: dict[Any, Any], rel_path: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    scopes: list[tuple[dict[Any, Any], str]] = [(document, "workflow")]
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        scopes.extend((job, f"job '{name}'") for name, job in jobs.items() if isinstance(job, dict))
    for scope, label in scopes:
        if str(scope.get("permissions", "")).strip() == "write-all":
            findings.append(
                _finding(
                    "GHA-004",
                    "medium",
                    "GITHUB_TOKEN granted write-all",
                    f"The {label} grants permissions: write-all. Declare only the scopes the jobs need (for example contents: read).",
                    rel_path,
                    key_line(scope, "permissions"),
                )
            )
    if "permissions" not in document:
        findings.append(
            _finding(
                "GHA-004",
                "low",
                "Workflow has no top-level permissions",
                "Without a top-level permissions: block the GITHUB_TOKEN gets the repository default, which may be write. "
                "Declare least-privilege permissions.",
                rel_path,
                1,
            )
        )
    return findings


def scan_github_workflow(file_path: str | Path) -> list[IaCFinding]:
    """Scan one GitHub Actions workflow file."""
    path = Path(file_path)
    if not path.is_file():
        return []
    content = path.read_text(encoding="utf-8", errors="replace")
    try:
        document = safe_load_with_lines(content)
    except yaml.YAMLError:
        return []
    if not isinstance(document, dict) or "jobs" not in document:
        return []
    rel_path = str(path)
    raw_lines = content.splitlines()
    steps = _steps(document)
    findings: list[IaCFinding] = []
    if "pull_request_target" in _triggers(document):
        findings.extend(_pr_head_checkouts(steps, rel_path))
    findings.extend(_unpinned_actions(steps, document, rel_path))
    findings.extend(_script_injections(steps, raw_lines, rel_path))
    findings.extend(_permissions(document, rel_path))
    return findings
