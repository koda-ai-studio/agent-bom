"""The result block a ``-q`` scan still prints: verdict, severity counts, exit reason, report path."""

from __future__ import annotations

from typing import Any

import click

from agent_bom.cli.agents._output import _is_null_device, _resolve_output_path
from agent_bom.cli.agents._stderr import stderr_notice
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.evidence.scan_run import effective_scan_run
from agent_bom.logging_config import json_logging_active

SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


def severity_counts(report: Any) -> dict[str, int]:
    """Unsuppressed findings of every category by effective severity, in display order."""
    counts: dict[str, int] = {}
    for finding in report.to_findings():
        if finding.suppressed:
            continue
        severity = str(finding.effective_severity() or "unknown").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return {severity: counts[severity] for severity in SEVERITY_ORDER if severity in counts}


def _report_path(opts: ScanOptions) -> str | None:
    if not opts.output or opts.output == "-" or _is_null_device(opts.output):
        return None
    return _resolve_output_path(opts.output, opts.output_format)


def quiet_summary_lines(opts: ScanOptions, st: ScanState, exit_code: int) -> list[str]:
    report = st.report
    counts = severity_counts(report) if report is not None else {}
    total = sum(counts.values())
    outcome = effective_scan_run(report).outcome.value if report is not None else "complete"
    packages = int(getattr(st, "total_packages", 0) or 0)
    by_severity = " · ".join(f"{count} {severity}" for severity, count in counts.items())
    findings = f"{total} finding(s) ({by_severity})" if total else "no findings"
    lines = [f"agent-bom: {'PASS' if exit_code == 0 else 'FAIL'} — {outcome} scan, {packages} package(s), {findings}"]
    if exit_code:
        reasons = list(getattr(st.ctx, "exit_reasons", None) or []) or ["see the report's scan_run and findings"]
        lines.extend(f"Exit {exit_code}: {reason}" for reason in reasons)
    report_path = _report_path(opts)
    if report_path:
        lines.append(f"Report: {report_path}")
    return lines


def print_quiet_summary(opts: ScanOptions, st: ScanState, exit_code: int) -> None:
    """Print the result block under ``-q``; progress and banners stay suppressed.

    stdout carries it unless stdout already carries a machine document (``-f json``
    with no ``-o``), in which case it goes to stderr so the document stays
    parseable. Under JSON logs or ``--agent-mode`` only the exit reasons are
    emitted, as notices, because stderr must stay machine-readable there.
    """
    if not opts.quiet:
        return
    stdout_has_document = opts.agent_mode or (opts.output_format != "console" and opts.output in {None, "-"})
    if opts.agent_mode or (stdout_has_document and json_logging_active()):
        for reason in getattr(st.ctx, "exit_reasons", None) or []:
            stderr_notice(f"exit {exit_code}: {reason}")
        return
    _echo(quiet_summary_lines(opts, st, exit_code), stdout_has_document=stdout_has_document)


def print_quiet_incomplete(exc: Exception, *, stdout_has_document: bool) -> None:
    """The ``-q`` result for a scan that stopped because its vulnerability evidence is incomplete."""
    if stdout_has_document and json_logging_active():
        stderr_notice(f"exit 1: {exc}")
        return
    _echo(["agent-bom: FAIL — incomplete scan, vulnerability data unavailable", f"Exit 1: {exc}"], stdout_has_document=stdout_has_document)


def _echo(lines: list[str], *, stdout_has_document: bool) -> None:
    for line in lines:
        click.echo(line, err=stdout_has_document)
