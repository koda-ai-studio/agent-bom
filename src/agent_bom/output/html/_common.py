"""Shared low-level helpers and colour constants for the HTML report."""

from __future__ import annotations

from agent_bom.core.severity import severity_display_label
from agent_bom.output.finding_views import sanitize_output_text, severity_value

_SEV_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#6b7280",
    "none": "#16a34a",
    "unknown": "#9ca3af",
}

# Max packages shown per server before collapsing
_PKG_PREVIEW = 15

# Client-side pagination: rows shown per page for large findings tables.
_PAGE_SIZE = 50


def _sev_badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev.lower().split(" ", 1)[0], "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;'
        f'font-size:.72rem;font-weight:700;letter-spacing:.04em">{sev.upper()}</span>'
    )


def _finding_sev_badge(finding) -> str:
    """HTML badge for a finding; a namespace-default band reads ``MEDIUM (UNSCORED)``."""
    sev = severity_value(finding)
    source = (getattr(finding, "evidence", None) or {}).get("severity_source")
    return _sev_badge(severity_display_label(sev, source)) if sev != "unknown" else _sev_badge(sev)


def _esc(s: object) -> str:
    return sanitize_output_text(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
