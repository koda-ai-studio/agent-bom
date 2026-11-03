"""HTML banner for accepted IaC exceptions: what was accepted, by whom, until when."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.output.html._common import _esc

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport

_MAX_ROWS = 200


def _row(finding: dict[str, Any]) -> str:
    record = finding.get("suppression") or {}
    location = f"{finding.get('file_path', '')}:{finding.get('line_number', '')}"
    cells = (
        finding.get("rule_id", ""),
        location,
        record.get("source", ""),
        record.get("owner") or "—",
        record.get("expires") or "no expiry",
        record.get("reason", ""),
    )
    return "<tr>" + "".join(f"<td>{_esc(str(cell))}</td>" for cell in cells) + "</tr>"


def iac_exceptions_banner(report: AIBOMReport) -> str:
    """``N accepted IaC exception(s)`` with the full list, plus expired/rejected counts. Empty when there are none."""
    data = getattr(report, "iac_findings_data", None)
    if not isinstance(data, dict):
        return ""
    suppressed = [row for row in data.get("suppressed") or [] if isinstance(row, dict)]
    raw_summary = data.get("exceptions")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    expired = int(summary.get("expired") or 0)
    expiring = int(summary.get("expiring_soon") or 0)
    rejected = int(summary.get("rejected") or 0)
    if not suppressed and not (expired or rejected):
        return ""
    notes = []
    if expired:
        notes.append(f"{expired} expired (findings active again)")
    if expiring:
        notes.append(f"{expiring} expiring within 14 days")
    if rejected:
        notes.append(f"{rejected} rejected by a non-waivable policy rule")
    note_html = f" &middot; {_esc(' · '.join(notes))}" if notes else ""
    rows = "".join(_row(row) for row in suppressed[:_MAX_ROWS])
    more = f'<p style="margin:6px 0 0">+{len(suppressed) - _MAX_ROWS} more in the JSON export</p>' if len(suppressed) > _MAX_ROWS else ""
    table = (
        '<table style="width:100%;margin-top:8px;font-size:.8rem;border-collapse:collapse">'
        "<thead><tr><th>Rule</th><th>Location</th><th>Source</th><th>Owner</th><th>Expires</th><th>Reason</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>{more}"
        if suppressed
        else ""
    )
    return (
        '<div id="iac-exceptions" style="background:#0f172a;border:1px solid #475569;border-radius:8px;'
        'padding:10px 16px;margin-bottom:12px;font-size:.85rem;color:#cbd5e1">'
        f"<details><summary><b>{len(suppressed)} accepted IaC exception(s)</b> &mdash; "
        f"retained as evidence, excluded from gates{note_html}</summary>{table}</details>"
        "</div>"
    )
