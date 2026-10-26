"""Console section for the Kubernetes workload inventory."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

_ROWS = 15


def _grants_by_account(inventory: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grants: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for grant in inventory.get("rbac_grants") or []:
        account = grant["service_account"]
        grants.setdefault((account["namespace"], account["name"]), []).append(grant)
    return grants


def _rbac_label(grants: list[dict[str, Any]]) -> str:
    if not grants:
        return "-"
    parts = []
    if any(g["wildcard"] for g in grants):
        parts.append("wildcard")
    if any(g["secrets"]["access"] in {"all", "named"} for g in grants):
        parts.append("reads secrets")
    if any(not g["role_resolved"] for g in grants):
        parts.append("unresolved role")
    return ", ".join(parts) or f"{len(grants)} binding(s)"


def _rows(section: dict[str, Any]) -> list[tuple[int, list[str]]]:
    rows = []
    for inventory in section.get("inventories") or []:
        grants = _grants_by_account(inventory)
        for workload in inventory.get("workloads") or []:
            scans = [c.get("scan") or {} for c in workload.get("containers") or []]
            vulns = sum(int(s.get("vulnerabilities") or 0) for s in scans)
            critical = sum(int(s.get("critical") or 0) for s in scans)
            scanned = sum(1 for s in scans if s.get("scanned"))
            account = (workload["namespace"], workload["service_account"])
            token = "" if workload.get("token_mounted") else " (no token)"
            rows.append(
                (
                    vulns,
                    [
                        f"{workload['kind']}/{workload['name']}",
                        workload["namespace"],
                        f"{scanned}/{len(scans)} scanned",
                        f"{vulns} ({critical} critical)" if scanned else "not scanned",
                        f"{workload['service_account']}{token}",
                        _rbac_label(grants.get(account, [])),
                        str(len(workload.get("secret_refs") or [])),
                    ],
                )
            )
    return sorted(rows, key=lambda row: (-row[0], row[1][1], row[1][0]))


def print_kubernetes_workloads(con: Console, section: dict[str, Any] | None) -> None:
    if not section:
        return
    rows = _rows(section)
    summary = section.get("summary") or {}
    con.print(
        f"\n[bold]Kubernetes workloads[/bold] [dim]{summary.get('workloads', 0)} workload(s), "
        f"{summary.get('images_scanned', 0)}/{summary.get('images', 0)} image(s) scanned, "
        f"{summary.get('workloads_with_vulnerabilities', 0)} with vulnerabilities[/dim]"
    )
    if not rows:
        return
    table = Table(show_edge=False, pad_edge=False, box=None)
    for column in ("Workload", "Namespace", "Images", "CVEs", "Service account", "RBAC", "Secrets"):
        table.add_column(column)
    for _vulns, cells in rows[:_ROWS]:
        table.add_row(*cells)
    con.print(table)
    if len(rows) > _ROWS:
        shown = f"Showing {_ROWS} of {len(rows)} workloads, most vulnerable first"
        con.print(f"  [dim]{shown}; full list in -f json (kubernetes_inventory).[/dim]")
