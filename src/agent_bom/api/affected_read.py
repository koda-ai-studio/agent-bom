"""Answer "am I affected?" for one advisory or package across the current estate.

The findings half reads the same merged scan and ingest queue ``/v1/findings``
serves, so its counts match the findings page. Matching is exact: an advisory
query matches the row's advisory id, a package query the row's package name
(and version when given); the free-text search only narrows the walk.

The reach half is the exploit story's at-risk groups for the matched
advisories on the latest graph snapshot: what the affected packages' hosts
reach. It is recorded topology, not proof of exploitation, and it names the
snapshot it read.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import Request

from agent_bom.api.finding_page_read import _list_findings_view_impl
from agent_bom.domain.finding_signal_filters import row_has_fix

_logger = logging.getLogger(__name__)

#: Bounds: rows walked, assets listed, advisories whose reach is read.
MAX_FINDINGS = 5000
MAX_ASSETS = 200
MAX_STORIES = 5
_ADVISORY = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|[A-Z][A-Z0-9]*-[A-Z0-9][A-Z0-9._:-]*\d[A-Z0-9._:-]*)$", re.I
)
_REACH_KINDS = ("agents", "mcp_servers", "tools", "credentials", "data_stores", "cloud_resources", "identities")


def parse_query(raw: str) -> dict[str, Any]:
    """An advisory id (CVE, GHSA, OSV-style) or a package as ``name`` or ``name@version``."""
    text = raw.strip()
    if _ADVISORY.match(text) and "@" not in text:
        return {"raw": raw, "kind": "advisory", "advisory": text.upper()}
    name, _, version = text.rpartition("@") if text.rfind("@") > 0 else (text, "", "")
    return {"raw": raw, "kind": "package", "package": name.strip().lower(), "version": version.strip() or None}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _advisory_ids(row: dict[str, Any]) -> set[str]:
    ids = {str(row.get(key) or "").strip().upper() for key in ("cve_id", "vulnerability_id")}
    aliases = row.get("aliases")
    ids.update(str(alias).strip().upper() for alias in aliases if alias) if isinstance(aliases, list) else None
    return {value for value in ids if value}


def _package(row: dict[str, Any]) -> tuple[str, str]:
    evidence, asset = _mapping(row.get("evidence")), _mapping(row.get("asset"))
    name = evidence.get("package_name") or row.get("package_name") or (asset.get("name") if asset.get("asset_type") == "package" else "")
    version = evidence.get("package_version") or row.get("package_version") or ""
    return str(name or "").strip(), str(version or "").strip()


def matches(row: dict[str, Any], query: dict[str, Any]) -> bool:
    if query["kind"] == "advisory":
        return query["advisory"] in _advisory_ids(row)
    name, version = _package(row)
    return name.lower() == query["package"] and (query["version"] is None or version == query["version"])


def _walk(request: Request, query: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Matched rows from the current queue, every lifecycle state, bounded by :data:`MAX_FINDINGS`."""
    search = query.get("advisory") or query.get("package")
    rows: list[dict[str, Any]] = []
    cursor: str | None = None
    walked = 0
    while walked < MAX_FINDINGS:
        page = _list_findings_view_impl(
            request,
            q=search,
            severity=None,
            scan_id=None,
            sort="effective_reach",
            limit=min(1000, MAX_FINDINGS - walked),
            offset=0,
            cursor=cursor,
            approximate_total=cursor is not None,
            status="all",
            window_days=0,
        )
        page_rows = [row for row in page.get("findings") or [] if isinstance(row, dict)]
        walked += len(page_rows)
        rows.extend(row for row in page_rows if matches(row, query))
        cursor = str(page.get("next_cursor") or "") or None
        if not cursor or not page_rows:
            return rows, False
    return rows, True


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(str(row.get("status") or "open").lower() for row in rows)
    exposed = sum(1 for row in rows if isinstance(row.get("risk_context"), dict) and row["risk_context"].get("internet_exposed") is True)
    fixable = sum(1 for row in rows if row_has_fix(row))
    return {
        "total": len(rows),
        "open": statuses.get("open", 0),
        "resolved": statuses.get("resolved", 0),
        "suppressed": sum(1 for row in rows if row.get("suppressed") is True),
        "severity": dict(Counter(str(row.get("severity") or "unknown").lower() for row in rows)),
        "kev": any(row.get("is_kev") is True for row in rows),
        "fix_available": fixable,
        "no_fix": len(rows) - fixable,
        "internet_exposed": exposed,
        "advisories": sorted({advisory for row in rows for advisory in _advisory_ids(row)})[:50],
        "packages": sorted({"@".join(part for part in _package(row) if part) for row in rows if _package(row)[0]})[:50],
    }


def _exposure(rows: list[dict[str, Any]]) -> dict[str, Any]:
    first = [str(row["first_seen"]) for row in rows if row.get("first_seen")]
    last = [str(row.get("last_seen") or row.get("last_observed")) for row in rows if row.get("last_seen") or row.get("last_observed")]
    resolved = [str(row["resolved_at"]) for row in rows if row.get("resolved_at")]
    return {
        "first_seen": min(first) if first else None,
        "last_seen": max(last) if last else None,
        "still_open": any(str(row.get("status") or "open").lower() == "open" for row in rows),
        "last_resolved_at": max(resolved) if resolved else None,
    }


def _asset(row: dict[str, Any]) -> dict[str, Any]:
    asset = _mapping(row.get("asset"))
    package, version = _package(row)
    return {
        "name": str(asset.get("name") or package or row.get("title") or ""),
        "asset_type": asset.get("asset_type"),
        "package": package or None,
        "version": version or None,
        "advisory": next(iter(sorted(_advisory_ids(row))), None),
        "status": row.get("status"),
        "severity": row.get("severity"),
        "provider": row.get("provider"),
        "environment": row.get("environment") or asset.get("environment"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen") or row.get("last_observed"),
        "fixed_version": row.get("fixed_version"),
        "finding_id": row.get("finding_id") or row.get("id"),
    }


def _story_reach(tenant_id: str, advisories: list[str]) -> dict[str, Any]:
    """At-risk groups of up to :data:`MAX_STORIES` advisories on the latest snapshot, merged by node."""
    from agent_bom.api.stores import _get_graph_store
    from agent_bom.graph.exploit_story_read import read_exploit_story

    items: dict[str, dict[str, dict[str, str]]] = {kind: {} for kind in _REACH_KINDS}
    walked: list[str] = []
    scan_id: str | None = None
    note = None
    try:
        store = _get_graph_store()
        for advisory in advisories[:MAX_STORIES]:
            story = read_exploit_story(store, tenant_id=tenant_id, scan_id=None, node_id=f"vuln:{advisory}")
            if not story:
                continue
            walked.append(advisory)
            scan_id = scan_id or story.get("scan_id")
            for group in (story.get("at_risk") or {}).get("groups") or []:
                bucket = items.setdefault(str(group.get("kind")), {})
                for item in group.get("items") or []:
                    bucket.setdefault(
                        str(item["id"]),
                        {
                            "id": str(item["id"]),
                            "label": str(item.get("label") or item["id"]),
                            "entity_type": str(item.get("entity_type") or ""),
                        },
                    )
    except NotImplementedError:
        note = "This graph backend does not support pinned reach reads."
    except Exception as exc:  # noqa: BLE001  # broad-except: reach is additive; the findings answer stands without it
        _logger.warning("Affected reach unavailable: %s", type(exc).__name__)
        note = "Graph reach is unavailable for this read."
    if len(advisories) > MAX_STORIES:
        note = f"Reach covers the first {MAX_STORIES} of {len(advisories)} matched advisories."
    listed = {kind: sorted(bucket.values(), key=lambda item: item["label"]) for kind, bucket in items.items() if bucket}
    return {
        "by_kind": {kind: len(values) for kind, values in listed.items()},
        "items": listed,
        "basis": "graph_snapshot" if walked else "unavailable" if note else "findings_only",
        "scan_id": scan_id,
        "advisories_walked": walked,
        "note": note,
    }


def _inventory(tenant_id: str, advisory: str | None) -> dict[str, Any]:
    """The advisory's ranges matched against stored inventory (``/v1/intel/advisories/{id}/affected``) as counts."""
    if advisory is None:
        return {"available": False, "note": "Inventory matching takes an advisory id."}
    from agent_bom.api.advisory_affected_read import tenant_affected_answer

    try:
        answer = tenant_affected_answer(tenant_id, advisory)
    except Exception as exc:  # noqa: BLE001  # broad-except: the inventory match is additive; findings still answer
        _logger.warning("Affected inventory match unavailable: %s", type(exc).__name__)
        return {"available": False, "note": "Inventory matching is unavailable for this read."}
    if answer is None:
        return {"available": False, "note": "No advisory record or stored finding names this id."}
    summary = answer.get("summary") or {}
    return {
        "available": True,
        "affected": int(summary.get("affected") or 0),
        "possibly_affected": int(summary.get("possibly_affected") or 0),
        "not_affected": int(summary.get("not_affected") or 0),
        "assets_examined": int(summary.get("assets_examined") or 0),
        "complete": answer.get("complete"),
        "source": (answer.get("advisory") or {}).get("source"),
        "href": f"/v1/intel/advisories/{quote(advisory)}/affected",
    }


def _verdict(exposure: dict[str, Any], has_rows: bool, inventory: dict[str, Any]) -> tuple[str, list[str]]:
    """Open findings or an inventory hit is affected; a distro-only hit is possibly; resolved-only is previously."""
    basis = (["findings"] if has_rows else []) + (
        ["inventory_match"] if inventory.get("affected") or inventory.get("possibly_affected") else []
    )
    if exposure["still_open"] or inventory.get("affected"):
        return "affected", basis
    if inventory.get("possibly_affected"):
        return "possibly_affected", basis
    return ("previously_affected" if has_rows else "not_found"), basis


def read_affected(request: Request, tenant_id: str, raw: str) -> dict[str, Any]:
    query = parse_query(raw)
    rows, truncated = _walk(request, query)
    summary = _summary(rows)
    reach = (
        _story_reach(tenant_id, summary["advisories"])
        if rows
        else {"by_kind": {}, "items": {}, "basis": "findings_only", "scan_id": None, "advisories_walked": [], "note": None}
    )
    reach["agents_on_findings"] = sorted(
        {str(agent) for row in rows for agent in row.get("graph_reachable_from_agents") or row.get("affected_agents") or []}
    )
    reach["servers_on_findings"] = sorted({str(server) for row in rows for server in row.get("affected_servers") or []})
    exposure = _exposure(rows)
    inventory = _inventory(tenant_id, query.get("advisory"))
    verdict, basis = _verdict(exposure, bool(rows), inventory)
    assets = [_asset(row) for row in rows]
    return {
        "tenant_id": tenant_id,
        "query": {key: query.get(key) for key in ("raw", "kind", "advisory", "package", "version")},
        "verdict": verdict,
        "verdict_basis": basis,
        "inventory": inventory,
        "findings": summary,
        "exposure": exposure,
        "assets": assets[:MAX_ASSETS],
        "assets_truncated": len(assets) > MAX_ASSETS,
        "reach": reach,
        "findings_truncated": truncated,
        "findings_href": "/findings?" + urlencode({"q": query.get("advisory") or query.get("package"), "status": "all"}),
    }


__all__ = ["MAX_FINDINGS", "MAX_STORIES", "matches", "parse_query", "read_affected"]
