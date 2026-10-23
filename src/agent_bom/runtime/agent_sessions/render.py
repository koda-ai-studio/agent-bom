"""Plain terminal rendering of the activity review; every value is already redacted."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_log_label

_TOP = 10


def _line(text: object) -> str:
    return sanitize_log_label(text, max_len=300)


def _servers(report: dict[str, Any]) -> list[str]:
    lines = ["", "MCP servers used"]
    for row in report["mcp_servers"][:_TOP] or []:
        tools = ", ".join(f"{tool['tool']} x{tool['calls']}" for tool in row["tools"][:5])
        lines.append("  " + _line(f"{row['agent']} / {row['server']}: {row['calls']} calls, last {row['last_used'][:10]} ({tools})"))
    if not report["mcp_servers"]:
        lines.append("  none in this window")
    lines += ["", "Configured but unused (candidates to remove)"]
    lines += ["  " + _line(f"{row['agent']} / {row['server']} in {row['config_path']}") for row in report["unused_servers"][:_TOP]]
    if not report["unused_servers"]:
        lines.append("  none")
    return lines


def _risks(report: dict[str, Any]) -> list[str]:
    total = report["summary"]["counts"]["risky_actions"]
    lines = ["", f"Risky actions ({total} occurrences, most severe first)"]
    by_category = ", ".join(f"{name} {row['occurrences']}" for name, row in report["risky_action_totals"].items())
    if by_category:
        lines.append("  " + _line(f"by category: {by_category}"))
    low = ", ".join(f"{reason} {row['occurrences']}" for reason, row in report["low_signal_writes"].items())
    if low:
        lines.append("  " + _line(f"not flagged, writes outside the cwd into the same repo, temp or agent state: {low}"))
    for row in report["risky_actions"][:_TOP]:
        lines.append(
            "  "
            + _line(f"[{row['severity']}] {row['category']} x{row['count']} last {row['last_seen'][:19]} {row['agent']}: {row['evidence']}")
        )
    if not report["risky_actions"]:
        lines.append("  none")
    return lines


def _packages(report: dict[str, Any]) -> list[str]:
    lines = ["", f"Packages installed or run ({len(report['installed_packages'])})"]
    for row in report["installed_packages"][:_TOP]:
        version = f"@{row['version']}" if row["version"] else ""
        lines.append("  " + _line(f"{row['ecosystem']}: {row['name']}{version} via {row['manager']} x{row['count']}"))
    return lines


def render_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [_line(summary["headline"])]
    builtin = ", ".join(f"{row['tool']} x{row['calls']}" for row in report["builtin_tools"][:8])
    if builtin:
        lines.append(_line(f"Built-in tools: {builtin}"))
    lines += _servers(report) + _risks(report) + _packages(report)
    if summary["recommendations"]:
        lines += ["", "Recommendations"] + ["  " + _line(f"{index}. {text}") for index, text in enumerate(summary["recommendations"], 1)]
    lines += ["", "Read locally only; nothing was sent. Full detail: agent-bom activity --format json"]
    return "\n".join(lines)
