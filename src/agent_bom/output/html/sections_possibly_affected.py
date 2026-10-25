"""HTML section for possibly-affected advisories (review items, never counted)."""

from __future__ import annotations

from typing import Any

from agent_bom.output.html._common import _esc
from agent_bom.output.possibly_affected import possibly_affected_rows

_HEADERS = ("Advisory", "Package", "Version", "Advisory severity", "Upstream fix", "Why it is undecided")


def _row(row: dict[str, Any]) -> str:
    cells = (
        row["id"],
        row["package"]["name"],
        row["package"]["version"],
        str(row.get("severity") or "unknown"),
        row.get("upstream_fixed_version") or "—",
        row["detail"],
    )
    return '<tr data-verdict="possibly_affected">' + "".join(f"<td>{_esc(cell)}</td>" for cell in cells) + "</tr>"


def possibly_affected_section(report: Any) -> str:
    rows = possibly_affected_rows(report)
    if not rows:
        return ""
    header = "".join(f"<th>{_esc(title)}</th>" for title in _HEADERS)
    return (
        '<section id="possibly-affected">'
        '<div class="sec-title">&#x2753; Possibly affected — verify distro advisory'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(rows)}</sup></div>'
        '<div class="panel"><p style="font-size:.8rem;color:#64748b;margin:0 0 8px">'
        "A distro package ships a product these advisories name, and no distro record decides it. "
        "Review items: not counted as vulnerabilities and never a severity-gate trigger.</p>"
        f'<div class="table-wrap"><table class="data-table"><thead><tr>{header}</tr></thead>'
        f"<tbody>{''.join(_row(row) for row in rows)}</tbody></table></div></div>"
        "</section>"
    )
