"""The affected-assets answer for the standalone CLI and local MCP server.

Kept apart from ``operator_advisories`` so the CLI's import path stays free of
the graph package; the answer adds graph node ids, which needs it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from agent_bom.db import schema
from agent_bom.db.operator_advisories import distro_verdicts, local_advisory
from agent_bom.db.schema import open_existing_db_readonly
from agent_bom.history import latest_report, load_report_or_sbom
from agent_bom.scanners.advisory_affected import MAX_LIMIT, affected_answer, feed_advisory_from_db, page_answer
from agent_bom.scanners.operator_advisory import OperatorAdvisory


def _local_feed_advisory(advisory_id: str) -> OperatorAdvisory | None:
    if not schema.DB_PATH.exists():
        return None
    try:
        conn = open_existing_db_readonly(schema.DB_PATH)
    except sqlite3.Error:
        return None
    try:
        return feed_advisory_from_db(conn, advisory_id)
    finally:
        conn.close()


def local_affected_answer(advisory_id: str, report_paths: list[Path] | None = None) -> dict[str, Any] | None:
    """The affected-assets answer from the local declaration (else the local feed record); ``None`` when unknown."""
    declared = local_advisory(advisory_id)
    advisory, source = (declared, "operator_advisory") if declared else (_local_feed_advisory(advisory_id), "feed")
    if advisory is None:
        return None
    paths = list(report_paths or [])
    if not paths:
        latest = latest_report()
        paths = [latest] if latest is not None else []
    reports = [load_report_or_sbom(path) for path in paths]
    with distro_verdicts() as verdict:
        return affected_answer(advisory, reports, source=source, distro_verdict=verdict)


def local_affected_body(advisory_id: str, report_paths: list[Path] | None = None) -> dict[str, Any] | None:
    """The whole local answer as one unpaged response body (what ``db advisory affected`` prints)."""
    answer = local_affected_answer(advisory_id, report_paths)
    if answer is None:
        return None
    body = page_answer(answer, tenant_id="local", limit=MAX_LIMIT)
    return {**body, "rows": answer["rows"], "count": len(answer["rows"]), "has_more": False, "next_cursor": None}
