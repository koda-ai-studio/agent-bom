"""Headline counts and up to three plain-language recommendations."""

from __future__ import annotations

from typing import Any


def _count(rows: list[dict[str, Any]], **match: str) -> int:
    """Occurrences, not grouped rows."""
    return sum(int(row.get("count", 1)) for row in rows if all(row.get(key) == value for key, value in match.items()))


def _recommendations(report: dict[str, Any]) -> list[str]:
    risky, unused, packages = report["risky_actions"], report["unused_servers"], report["installed_packages"]
    candidates: list[str] = []
    if unused:
        names = ", ".join(sorted({f"{row['server']} ({row['agent']})" for row in unused})[:3])
        candidates.append(
            f"Remove {len(unused)} MCP server(s) your agents never called in this window, such as {names}: "
            "configured servers are attack surface even when unused."
        )
    pipe = _count(risky, category="pipe_to_shell")
    if pipe:
        candidates.append(
            f"Agents piped downloaded scripts into a shell {pipe} time(s); require review before running remote install scripts."
        )
    destructive = _count(risky, category="destructive_command", severity="high")
    if destructive:
        candidates.append(
            f"Review {destructive} high-risk destructive command(s) such as force pushes; deny them in the agent's permission settings."
        )
    secrets = _count(risky, category="secret_file_read")
    if secrets:
        candidates.append(
            f"Agents read secret-like files {secrets} time(s); deny reads of .env, keys and credential files in agent permissions."
        )
    outside = _count(risky, category="write_outside_project")
    if outside:
        candidates.append(f"Agents wrote outside their project {outside} time(s); limit write access to the project directory.")
    if packages:
        first = packages[0]
        candidates.append(
            f"Check the {len(packages)} package(s) agents installed for known vulnerabilities, starting with "
            f"`agent-bom check {first['name']} --ecosystem {first['ecosystem']}`."
        )
    return candidates[:3]


def build_summary(report: dict[str, Any]) -> dict[str, Any]:
    totals, risky = report["totals"], report["risky_actions"]
    counts = {
        "sessions": totals["sessions"],
        "tool_calls": totals["tool_calls"],
        "mcp_calls": totals["mcp_calls"],
        "mcp_servers_used": len(report["mcp_servers"]),
        "unused_servers": len(report["unused_servers"]),
        "high_risk_actions": _count(risky, severity="high"),
        "risky_actions": sum(total["occurrences"] for total in report["risky_action_totals"].values()),
        "installed_packages": len(report["installed_packages"]),
    }
    label = report["window"]["label"]
    found = any(source["files_read"] for source in report["sources"].values())
    if not found:
        headline = f"No Claude Code or Codex session history found for {label.lower()}."
    else:
        headline = (
            f"{label}: {counts['tool_calls']} tool calls in {counts['sessions']} sessions; "
            f"{counts['high_risk_actions']} high-risk actions, {counts['unused_servers']} unused MCP servers, "
            f"{counts['installed_packages']} packages installed."
        )
    if report.get("truncated"):
        headline += " Read limits were reached, so counts are partial."
    return {"headline": headline, "counts": counts, "recommendations": _recommendations(report)}
