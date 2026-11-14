"""The result block a ``-q`` scan still prints: verdict, severity counts, exit reason, report path."""

from __future__ import annotations

import logging
from typing import Any

import click

from agent_bom.cli.agents._output import _FORMAT_OUTPUT_RULES, _is_null_device, _resolve_output_path
from agent_bom.cli.agents._stderr import VERDICT_LOGGER, log_record, stderr_notice
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
    # Without an explicit format, the writer infers it from the extension and
    # writes to the path as given (image -o report.json), so report that path.
    if opts.output_format not in _FORMAT_OUTPUT_RULES:
        return str(opts.output)
    return _resolve_output_path(opts.output, opts.output_format)


def quiet_verdict(opts: ScanOptions, st: ScanState, exit_code: int, *, forced_reason: str | None = None) -> dict[str, Any]:
    """The structured result: verdict, outcome, counts, exit code, reasons and report path.

    ``forced_reason`` is the default severity gate's failure that ``--exit-zero``
    turned into exit 0: the verdict stays FAIL and ``exit_forced_by`` names the flag.
    """
    report = st.report
    counts = severity_counts(report) if report is not None else {}
    forced = bool(forced_reason) and exit_code == 0
    reasons = list(getattr(st.ctx, "exit_reasons", None) or []) if exit_code else ([forced_reason] if forced else [])
    return {
        "verdict": "FAIL" if exit_code or forced else "PASS",
        "outcome": effective_scan_run(report).outcome.value if report is not None else "complete",
        "packages": int(getattr(st, "total_packages", 0) or 0),
        "findings": sum(counts.values()),
        "counts": counts,
        "exit_code": exit_code,
        "exit_forced_by": "--exit-zero" if forced else None,
        "reasons": [str(reason) for reason in reasons] or (["see the report's scan_run and findings"] if exit_code else []),
        "report": _report_path(opts),
    }


def _headline(verdict: dict[str, Any]) -> str:
    by_severity = " · ".join(f"{count} {severity}" for severity, count in verdict["counts"].items())
    findings = f"{verdict['findings']} finding(s) ({by_severity})" if verdict["findings"] else "no findings"
    forced = f" (exit forced to {verdict['exit_code']} by {verdict['exit_forced_by']})" if verdict.get("exit_forced_by") else ""
    return f"agent-bom: {verdict['verdict']}{forced} — {verdict['outcome']} scan, {verdict['packages']} package(s), {findings}"


def quiet_summary_lines(opts: ScanOptions, st: ScanState, exit_code: int, *, forced_reason: str | None = None) -> list[str]:
    verdict = quiet_verdict(opts, st, exit_code, forced_reason=forced_reason)
    lines = [_headline(verdict)]
    exit_label = f"Exit {exit_code} (forced)" if verdict["exit_forced_by"] else f"Exit {exit_code}"
    lines.extend(f"{exit_label}: {reason}" for reason in verdict["reasons"])
    if verdict["report"]:
        lines.append(f"Report: {verdict['report']}")
    return lines


def _log_verdict(verdict: dict[str, Any]) -> None:
    level = logging.WARNING if verdict["verdict"] == "FAIL" else logging.INFO
    log_record(_headline(verdict), level=level, context=verdict, logger_name=VERDICT_LOGGER)


def print_quiet_summary(opts: ScanOptions, st: ScanState, exit_code: int, *, forced_reason: str | None = None) -> None:
    """Print the result block under ``-q``; progress and banners stay suppressed.

    stdout carries it unless stdout already carries a machine document (``-f json``
    with no ``-o``), in which case it goes to stderr so the document stays
    parseable. Under JSON logs the block is one ``agent_bom.verdict`` record
    (WARNING for FAIL, INFO for PASS) and stdout stays empty; under
    ``--agent-mode`` only the exit reasons are emitted, as warnings.
    """
    if not opts.quiet:
        return
    stdout_has_document = opts.agent_mode or (opts.output_format != "console" and opts.output in {None, "-"})
    if opts.agent_mode:
        for reason in getattr(st.ctx, "exit_reasons", None) or []:
            stderr_notice(f"exit {exit_code}: {reason}", level=logging.WARNING)
        return
    if json_logging_active():
        _log_verdict(quiet_verdict(opts, st, exit_code, forced_reason=forced_reason))
        return
    _echo(quiet_summary_lines(opts, st, exit_code, forced_reason=forced_reason), stdout_has_document=stdout_has_document)


def print_quiet_incomplete(exc: Exception, *, stdout_has_document: bool) -> None:
    """The ``-q`` result for a scan that stopped because its vulnerability evidence is incomplete."""
    if json_logging_active():
        log_record(
            "agent-bom: FAIL — incomplete scan, vulnerability data unavailable",
            level=logging.WARNING,
            context={"verdict": "FAIL", "outcome": "incomplete", "exit_code": 1, "reasons": [str(exc)], "report": None},
            logger_name=VERDICT_LOGGER,
        )
        return
    _echo(["agent-bom: FAIL — incomplete scan, vulnerability data unavailable", f"Exit 1: {exc}"], stdout_has_document=stdout_has_document)


def _echo(lines: list[str], *, stdout_has_document: bool) -> None:
    for line in lines:
        click.echo(line, err=stdout_has_document)
