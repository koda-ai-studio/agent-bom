"""Print what changed since the last local scan of the same target, then remember this one.

Console-only: machine-readable outputs, exit codes and gates are untouched.
Nothing is stored in CI, in demo mode, for dry runs or when
``AGENT_BOM_NO_SCAN_MEMORY`` is set.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from agent_bom.ci_detect import detect_ci_environment
from agent_bom.cli._common import logger
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState

_PATH_FIELDS = ("path", "project", "config_dir", "inventory", "sbom_file", "gha_path")
_MULTI_PATH_FIELDS = ("tf_dirs", "code_paths", "filesystem_paths", "skill_paths", "image_tars")
_PLAIN_FIELDS = ("repo_url", "images", "no_discover", "inventory_only", "skill_only", "k8s", "aws", "os_packages")


def _abs(value: Any) -> str:
    try:
        return str(Path(str(value)).expanduser().resolve())
    except (OSError, RuntimeError, ValueError):
        return str(value)


def target_parts(opts: ScanOptions) -> dict[str, Any]:
    parts: dict[str, Any] = {"cwd": _abs(os.getcwd())}
    for name in _PATH_FIELDS:
        value = getattr(opts, name, None)
        if value:
            parts[name] = _abs(value)
    for name in _MULTI_PATH_FIELDS:
        values = getattr(opts, name, None) or ()
        if values:
            parts[name] = sorted(_abs(v) for v in values)
    for name in _PLAIN_FIELDS:
        value = getattr(opts, name, None)
        if value:
            parts[name] = sorted(value) if isinstance(value, (list, tuple)) else value
    return parts


def _eligible(opts: ScanOptions) -> bool:
    from agent_bom.storage import last_scan_summary

    if last_scan_summary.disabled() or detect_ci_environment().get("is_ci"):
        return False
    return not (opts.demo or opts.dry_run or opts.no_scan)


def _console_visible(opts: ScanOptions) -> bool:
    return opts.output_format == "console" and not opts.output and not opts.quiet and not opts.agent_mode


def remember_and_report(opts: ScanOptions, st: ScanState) -> bool:
    """Print the delta header when a previous summary exists; return True on a first scan of this target."""
    if not _eligible(opts) or not isinstance(st.current_report_json, dict):
        return False
    from agent_bom.storage import last_scan_summary as memory

    try:
        key = memory.target_key(target_parts(opts))
        outcome = str((st.current_report_json.get("scan_run") or {}).get("outcome") or "complete")
        current = memory.build_summary(st.current_report_json, outcome=outcome)
        previous = memory.load_summary(key)
        if previous is not None and _console_visible(opts):
            st.con.print(memory.delta_line(memory.compare(previous, current)))
        memory.save_summary(key, current)
        return previous is None
    except Exception as exc:  # noqa: BLE001 - scan memory is a convenience and must never break a scan
        logger.debug("Last-scan summary skipped: %s", type(exc).__name__)
        return False
