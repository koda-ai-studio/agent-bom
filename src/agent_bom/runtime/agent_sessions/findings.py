"""Risky actions and installed packages derived from redacted call views."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from agent_bom.runtime.agent_sessions.packages import packages_from_command
from agent_bom.runtime.agent_sessions.risk import SEVERITY_RANK, Risk, classify_command, is_secret_path, outside_root, write_severity
from agent_bom.runtime.agent_sessions.views import CallView, later

MAX_ROWS_PER_CATEGORY = 25
MAX_SESSION_IDS = 5


def _risks(view: CallView) -> list[Risk]:
    risks: list[Risk] = []
    if view.action == "exec" and view.command:
        risks.extend(classify_command(view.command))
        if packages_from_command(view.command):
            risks.append(Risk("package_install", "low", view.command))
    for path in view.paths:
        if view.action == "read" and is_secret_path(path):
            risks.append(Risk("secret_file_read", "medium", path))
        if view.action == "write" and outside_root(path, view.project_root):
            risks.append(Risk("write_outside_project", write_severity(path), path))
    return risks


def _group(views: Iterable[CallView]) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """One row per (category, severity, agent, evidence); repeats become a count."""
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for view in views:
        for risk in _risks(view):
            row = groups.setdefault(
                (risk.category, risk.severity, view.agent, risk.evidence),
                {
                    "category": risk.category,
                    "severity": risk.severity,
                    "agent": view.agent,
                    "tool": view.tool,
                    "project": view.project_root,
                    "evidence": risk.evidence,
                    "count": 0,
                    "first_seen": view.timestamp,
                    "last_seen": "",
                    "session_ids": [],
                },
            )
            row["count"] += 1
            row["last_seen"] = later(row["last_seen"], view.timestamp)
            row["first_seen"] = row["first_seen"] if later(row["first_seen"], view.timestamp) == view.timestamp else view.timestamp
            if view.session_id not in row["session_ids"] and len(row["session_ids"]) < MAX_SESSION_IDS:
                row["session_ids"].append(view.session_id)
    return groups


def risky_actions(views: Iterable[CallView]) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]]]:
    """Grouped rows most severe first, at most ``MAX_ROWS_PER_CATEGORY`` per category, plus full totals."""
    rows = sorted(_group(views).values(), key=lambda row: row["last_seen"], reverse=True)
    rows.sort(key=lambda row: (SEVERITY_RANK.get(row["severity"], 9), -row["count"]))
    totals: dict[str, dict[str, int]] = {}
    shown: list[dict[str, Any]] = []
    for row in rows:
        total = totals.setdefault(row["category"], {"occurrences": 0, "distinct": 0, "shown": 0})
        total["occurrences"] += row["count"]
        total["distinct"] += 1
        if total["shown"] < MAX_ROWS_PER_CATEGORY:
            total["shown"] += 1
            shown.append(row)
    for row in shown:
        row["session_ids"].sort()
    return shown, dict(sorted(totals.items()))


def installed_packages(views: Iterable[CallView]) -> list[dict[str, Any]]:
    found: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for view in views:
        if view.action != "exec" or not view.command:
            continue
        for package in packages_from_command(view.command):
            row = found.setdefault(
                (package.ecosystem, package.name, package.version),
                {
                    "ecosystem": package.ecosystem,
                    "name": package.name,
                    "version": package.version,
                    "manager": package.manager,
                    "kind": package.kind,
                    "count": 0,
                    "last_seen": "",
                    "agents": [],
                },
            )
            row["count"] += 1
            row["last_seen"] = later(row["last_seen"], view.timestamp)
            if view.agent not in row["agents"]:
                row["agents"].append(view.agent)
    return sorted(found.values(), key=lambda row: (row["ecosystem"], row["name"], row["version"] or ""))
