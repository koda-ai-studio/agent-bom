"""HTTP stages that check stored findings stay equivalent through update, delete, retention and rebuild.

The update/delete push rescans a mutated copy of the estate (one vulnerable
package removed everywhere, another added to one more agent) and pushes it as
the same source. Afterwards the stored rows must equal the new scan field for
field, ``/v1/findings`` must show exactly the new open set, the removed
finding must be resolved rather than gone, and the graph must no longer carry
the removed package: reads served before the push must not be reused after it.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from scripts.perf.workflow_equivalence import (
    FindingKey,
    finding_key,
    finding_projections,
    lifecycle_mismatches,
    mutate_inventory,
    projection_digest,
    projection_mismatches,
)
from scripts.perf.workflow_profiles import MockUpstream, cli_push_body, expected_findings, vulnerable_versions

_OPEN = {"open", "reopened"}
GRAPH_REFRESH_DEADLINE_SECONDS = 60.0
# Identity a resolved row must keep so a reader can still tell which package was fixed.
RESOLVED_IDENTITY_FIELDS = ("package", "package_version", "ecosystem", "scan_id")


async def stored_rows(http: Any, job_id: str) -> list[dict[str, Any]]:
    """Every stored blast-radius row for ``job_id``, read back through the paged result-section API."""
    rows: list[dict[str, Any]] = []
    offset: int | None = 0
    while offset is not None:
        response, _ = await http.call("GET", f"/v1/scan/{job_id}/result/blast_radius?offset={offset}&limit=1000")
        if response.status_code != 200:
            raise RuntimeError(f"stored findings unreadable: {response.status_code} {response.text[:200]}")
        page = response.json()
        rows.extend(page.get("items") or [])
        offset = page.get("next_offset")
    return rows


async def findings_view(http: Any) -> dict[FindingKey, dict[str, Any]]:
    """``/v1/findings?status=all`` vulnerability rows grouped by ``(advisory, package, version)``."""
    rows: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        url = "/v1/findings?status=all&limit=1000" + (f"&cursor={quote(cursor)}" if cursor else "")
        response, _ = await http.call("GET", url)
        if response.status_code != 200:
            raise RuntimeError(f"/v1/findings failed: {response.status_code} {response.text[:200]}")
        body = response.json()
        rows.extend(body.get("findings") or [])
        cursor = body.get("next_cursor")
        if not cursor:
            break
    view: dict[FindingKey, dict[str, Any]] = {}
    for row in rows:
        if row.get("finding_class") != "vulnerability" or not row.get("vulnerability_id"):
            continue
        version = str(row.get("package_version") or "")
        # /v1/findings labels the package "name@version".
        package = str(row.get("package") or "").removesuffix(f"@{version}")
        key = (str(row["vulnerability_id"]), package, version)
        entry = view.setdefault(key, {"ids": set(), "first_seen": None, "last_seen": None, "statuses": set()})
        entry["ids"].add(str(row.get("finding_id") or row.get("id")))
        entry["statuses"].add(str(row.get("status")))
        first, last = row.get("first_seen"), row.get("last_seen")
        entry["first_seen"] = min(filter(None, (entry["first_seen"], first)), default=None)
        entry["last_seen"] = max(filter(None, (entry["last_seen"], last)), default=None)
    return {
        key: {**entry, "finding_id": ",".join(sorted(entry["ids"])), "ids": sorted(entry["ids"]), "statuses": sorted(entry["statuses"])}
        for key, entry in sorted(view.items())
    }


def _keys_digest(keys: set[FindingKey]) -> str:
    from scripts.perf.workflow_budget import findings_digest

    return findings_digest(keys)


def open_keys(view: dict[FindingKey, dict[str, Any]]) -> set[FindingKey]:
    return {key for key, entry in view.items() if _OPEN & set(entry["statuses"])}


async def package_nodes(http: Any, name: str, version: str) -> int:
    """Graph package nodes labelled ``name@version`` in the current graph."""
    response, _ = await http.call("GET", f"/v1/graph/search?q={quote(name)}&limit=200")
    if response.status_code != 200:
        return -1
    results = response.json().get("results") or []
    return sum(1 for node in results if node.get("entity_type") == "package" and node.get("label") == f"{name}@{version}")


async def resolved_rows(http: Any, vulnerability_id: str) -> list[dict[str, Any]]:
    """``/v1/findings?status=resolved`` rows for one advisory."""
    response, _ = await http.call("GET", "/v1/findings?status=resolved&limit=1000")
    if response.status_code != 200:
        raise RuntimeError(f"/v1/findings?status=resolved failed: {response.status_code}")
    return [row for row in response.json().get("findings") or [] if row.get("vulnerability_id") == vulnerability_id]


async def graph_refresh(http: Any, name: str, version: str, deadline: float = GRAPH_REFRESH_DEADLINE_SECONDS) -> tuple[int, float]:
    """Poll until the current graph drops ``name@version``; the current graph is rebuilt asynchronously."""
    began = time.monotonic()
    while True:
        remaining = await package_nodes(http, name, version)
        elapsed = time.monotonic() - began
        if remaining == 0 or elapsed > deadline:
            return remaining, round(elapsed, 2)
        await asyncio.sleep(0.25)


def _scan_mutated(report: dict[str, Any], inventory: dict[str, Any], path: Path, scan: Any, mocked: Any, guard: Any) -> tuple[Any, ...]:
    """Rewrite the inventory file in place, as an operator updating it would, and rescan it."""
    mutated, change = mutate_inventory(report, inventory)
    path.write_text(json.dumps(mutated), encoding="utf-8")
    output = path.with_name("report-mutated.json")
    with guard() as network, mocked(MockUpstream(vulnerable=vulnerable_versions(report))):
        scan(path, output)
    if network.blocked:
        raise RuntimeError(f"mutated scan attempted live network: {network.blocked}")
    body = output.read_bytes()
    return body, json.loads(body).get("blast_radius") or [], expected_findings(report, mutated), change


async def update_delete(
    http: Any,
    *,
    report: dict[str, Any],
    inventory: dict[str, Any],
    inventory_path: Path,
    source_id: str,
    before: dict[FindingKey, Any],
) -> dict[str, Any]:
    """Push the mutated estate and return every equivalence check on the stored and served state."""
    from scripts.perf.workflow_budget import _push, _run_cli_scan, mocked_upstream, network_guard

    body, scanned, expected, change = await asyncio.to_thread(
        _scan_mutated, report, inventory, inventory_path, _run_cli_scan, mocked_upstream, network_guard
    )
    deleted, widened = change["deleted"], change["widened"]
    graph_before = await package_nodes(http, deleted[1], deleted[2])
    pushed = await _push(http, cli_push_body(body, source_id=source_id), 600)
    stored = await stored_rows(http, str(pushed["job_id"]))
    after = await findings_view(http)
    resolved = await resolved_rows(http, deleted[0])
    remaining, refresh_seconds = await graph_refresh(http, deleted[1], deleted[2])
    stored_scope = finding_projections(stored).get(widened, {}).get("scope.affected_agents") or []
    return {
        "status": pushed["status"],
        "stored_digest": _keys_digest({finding_key(row) for row in stored}),
        "stored_projection_digest": projection_digest(stored),
        "change": {"deleted": "|".join(deleted), "widened": "|".join(widened), "added_agent": change["added_agent"]},
        "scanned_matches_expected": {finding_key(row) for row in scanned} == expected,
        "stored_mismatches": projection_mismatches(finding_projections(scanned), finding_projections(stored))[:10],
        "open_matches_expected": open_keys(after) == expected,
        "open_unexpected": sorted("|".join(key) for key in open_keys(after) - expected)[:10],
        "open_missing": sorted("|".join(key) for key in expected - open_keys(after))[:10],
        "deleted_still_open": deleted in open_keys(after),
        "deleted_resolved": any(row.get("resolution_reason") == "no_longer_detected" for row in resolved),
        "resolved_row_missing_identity": sorted({field for row in resolved for field in RESOLVED_IDENTITY_FIELDS if not row.get(field)}),
        "widened_scope_has_added_agent": json.dumps(change["added_agent"]) in stored_scope,
        "graph_package_nodes_before": graph_before,
        "graph_package_nodes_after": remaining,
        "graph_refresh_seconds": refresh_seconds,
        "lifecycle_mismatches": lifecycle_mismatches(before, after)[:10],
    }


def update_delete_failures(result: dict[str, Any]) -> list[str]:
    """Every failed update/delete check, as a readable list; empty when equivalent."""
    failures = [
        key for key in ("scanned_matches_expected", "open_matches_expected", "widened_scope_has_added_agent") if not result.get(key)
    ]
    failures += [f"stored {item}" for item in result.get("stored_mismatches") or []]
    failures += [f"lifecycle {item}" for item in result.get("lifecycle_mismatches") or []]
    if result.get("deleted_still_open") or not result.get("deleted_resolved"):
        failures.append("deleted finding was not resolved as no_longer_detected")
    if result.get("graph_package_nodes_before", 0) < 1 or result.get("graph_package_nodes_after") != 0:
        failures.append(f"graph package nodes {result.get('graph_package_nodes_before')} -> {result.get('graph_package_nodes_after')}")
    return failures


def known_gaps(equivalence: dict[str, Any]) -> list[str]:
    """Product gaps the harness measures but does not fail on; each has a strict xfail test."""
    missing = (equivalence.get("update_delete") or {}).get("resolved_row_missing_identity")
    return [f"resolved row lost identity fields: {', '.join(missing)}"] if missing else []


def ingest_equivalence(scanned: list[dict[str, Any]], stored: list[dict[str, Any]], view: dict[FindingKey, Any]) -> dict[str, Any]:
    """Stored rows equal the scan field for field, and ``/v1/findings`` serves exactly the stored set as open."""
    keys = {finding_key(row) for row in stored}
    return {
        "stored_mismatches": projection_mismatches(finding_projections(scanned), finding_projections(stored))[:10],
        "open_matches_stored": open_keys(view) == keys,
        "open_count": len(open_keys(view)),
    }


def rebuild_equivalence(
    stored: list[dict[str, Any]],
    rebuilt: list[dict[str, Any]],
    before: dict[FindingKey, Any],
    after: dict[FindingKey, Any],
    expected: set[FindingKey],
) -> dict[str, Any]:
    """After retention and a rebuild: same fields as the first stored copy, same open set, durable ids and first_seen."""
    return {
        "rebuilt_mismatches": projection_mismatches(finding_projections(stored), finding_projections(rebuilt))[:10],
        "open_matches_expected": open_keys(after) == expected,
        "lifecycle_mismatches": lifecycle_mismatches(before, after)[:10],
    }


def equivalence_failures(equivalence: dict[str, Any]) -> list[str]:
    """Every failed equivalence check across ingest, update/delete and rebuild; empty when equivalent."""
    failures: list[str] = []
    ingest = equivalence.get("ingest")
    if ingest:
        failures += [f"ingest stored {item}" for item in ingest["stored_mismatches"]]
        if not ingest["open_matches_stored"]:
            failures.append("ingest: open findings differ from stored findings")
    if equivalence.get("update_delete"):
        failures += [f"update_delete: {item}" for item in update_delete_failures(equivalence["update_delete"])]
    rebuild = equivalence.get("rebuild")
    if rebuild:
        failures += [f"rebuild {item}" for item in rebuild["rebuilt_mismatches"]]
        failures += [f"rebuild lifecycle {item}" for item in rebuild["lifecycle_mismatches"]]
        if not rebuild["open_matches_expected"]:
            failures.append("rebuild: open findings differ from the original estate")
    return failures
