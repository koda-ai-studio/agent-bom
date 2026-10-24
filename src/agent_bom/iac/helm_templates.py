"""Helm chart ``templates/`` evaluation.

Templates are Go-templated YAML, so parsing them as Kubernetes manifests fails
and used to be counted as a clean Kubernetes scan. When ``helm`` is on PATH the
chart is rendered with its default values (``helm template``, local only, no
cluster access) and the rendered manifests run through the Kubernetes rules;
each finding is mapped back to the template file and, where the rendered line
appears verbatim in the template, to its line. Without ``helm`` (or when
rendering fails) the templates are scanned textually for the host-escape keys
below, and the coverage reason says rendering was skipped.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.iac.kubernetes import scan_k8s_text
from agent_bom.iac.models import IaCFinding

_RENDER_TIMEOUT_SECONDS = 60
_SOURCE_RE = re.compile(r"^# Source: (.+)$", re.MULTILINE)
_TEXTUAL_RULES: tuple[tuple[str, str, str, str], ...] = (
    ("privileged", "K8S-001", "critical", "Privileged container"),
    ("hostNetwork", "K8S-002", "high", "hostNetwork enabled"),
    ("hostPID", "K8S-003", "high", "hostPID enabled"),
    ("hostIPC", "K8S-003", "high", "hostIPC enabled"),
    ("allowPrivilegeEscalation", "K8S-009", "high", "Privilege escalation allowed"),
)
_TEXTUAL_RE = re.compile(r"^\s*(" + "|".join(rule[0] for rule in _TEXTUAL_RULES) + r")\s*:\s*[\"']?true[\"']?\s*(?:#.*)?$")
_TEXTUAL_KEYS = ", ".join(rule[0] for rule in _TEXTUAL_RULES)


@dataclass
class ChartTemplateResult:
    findings: list[IaCFinding] = field(default_factory=list)
    files: int = 0
    reason: str = ""


def chart_root_for_template(path: Path) -> Path | None:
    """The chart directory when ``path`` sits under a chart's ``templates/``."""
    for parent in path.parents:
        if parent.name == "templates" and (parent.parent / "Chart.yaml").is_file():
            return parent.parent
    return None


def _template_files(chart_root: Path) -> list[Path]:
    templates = chart_root / "templates"
    return sorted(p for p in templates.rglob("*") if p.is_file() and p.suffix in {".yaml", ".yml", ".tpl"})


def _render(helm: str, chart_root: Path) -> tuple[str | None, str]:
    try:
        completed = subprocess.run(  # nosec B603 - fixed argv from shutil.which, no shell
            [helm, "template", str(chart_root), "--skip-schema-validation"],
            capture_output=True,
            text=True,
            timeout=_RENDER_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, type(exc).__name__
    if completed.returncode != 0:
        first = (completed.stderr or "").strip().splitlines()
        return None, first[0][:160] if first else f"exit {completed.returncode}"
    return completed.stdout, ""


def _template_line(template_lines: list[str], rendered_line: str) -> int:
    wanted = rendered_line.strip()
    if wanted:
        for number, line in enumerate(template_lines, start=1):
            if line.strip() == wanted:
                return number
        key = wanted.split(":", 1)[0].lstrip("- ").strip()
        if key:
            for number, line in enumerate(template_lines, start=1):
                if re.match(rf"^\s*-?\s*{re.escape(key)}\s*:", line):
                    return number
    return 1


def _scan_rendered(output: str, chart_root: Path, rel_prefix: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    sources = list(_SOURCE_RE.finditer(output))
    for index, source in enumerate(sources):
        end = sources[index + 1].start() if index + 1 < len(sources) else len(output)
        section = output[source.end() : end]
        # "<chart name>/templates/x.yaml" (or "<chart>/charts/<sub>/templates/x.yaml").
        template_rel = source.group(1).strip().split("/", 1)[-1]
        template_path = chart_root / template_rel
        try:
            template_lines = template_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            template_lines = []
        rendered_lines = section.splitlines()
        for finding in scan_k8s_text(section, template_rel):
            rendered = rendered_lines[finding.line_number - 1] if 0 < finding.line_number <= len(rendered_lines) else ""
            finding.line_number = _template_line(template_lines, rendered)
            finding.file_path = f"{rel_prefix}{template_rel}"
            finding.repository_relative_path = finding.file_path
            findings.append(finding)
    return findings


def _scan_textually(chart_root: Path, rel_prefix: str) -> list[IaCFinding]:
    rules = {key: (rule_id, severity, title) for key, rule_id, severity, title in _TEXTUAL_RULES}
    findings: list[IaCFinding] = []
    for template in _template_files(chart_root):
        rel = f"{rel_prefix}{template.relative_to(chart_root).as_posix()}"
        try:
            lines = template.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            match = _TEXTUAL_RE.match(line)
            if not match:
                continue
            rule_id, severity, title = rules[match.group(1)]
            findings.append(
                IaCFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    message=f"Helm template sets {match.group(1)}: true (found textually; the chart was not rendered).",
                    file_path=rel,
                    line_number=number,
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.1", "NIST-AC-6"],
                    repository_relative_path=rel,
                )
            )
    return findings


def scan_chart_templates(chart_root: Path, walk_root: Path) -> ChartTemplateResult:
    """Evaluate one chart's templates; ``reason`` states how they were evaluated."""
    files = _template_files(chart_root)
    rel_prefix = chart_root.relative_to(walk_root).as_posix() + "/" if chart_root != walk_root else ""
    result = ChartTemplateResult(files=len(files))
    if not files:
        return result
    helm = shutil.which("helm")
    failure = "helm not on PATH"
    if helm:
        output, error = _render(helm, chart_root)
        if output is not None:
            result.findings = _scan_rendered(output, chart_root, rel_prefix)
            result.reason = f"{rel_prefix or './'}templates rendered with helm template (default values)"
            return result
        failure = f"helm template failed: {error}"
    result.findings = _scan_textually(chart_root, rel_prefix)
    result.reason = f"{failure}; {rel_prefix or './'}templates scanned textually for {_TEXTUAL_KEYS} only, rendering skipped"
    return result
