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
        return "no bindings"
    parts = []
    if any(g["wildcard"] for g in grants):
        parts.append("wildcard")
    if any(g["secrets"]["access"] in {"all", "named"} for g in grants):
        parts.append("reads secrets")
    if any(not g["role_resolved"] for g in grants):
        parts.append("unresolved role")
    return ", ".join(parts) or f"{len(grants)} binding(s)"


def _cve_label(scans: list[dict[str, Any]]) -> str:
    scanned = [scan for scan in scans if scan.get("scanned")]
    if not scanned:
        return "not scanned"
    vulns = sum(int(scan.get("vulnerabilities") or 0) for scan in scanned)
    critical = sum(int(scan.get("critical") or 0) for scan in scanned)
    partial = f", {len(scanned)}/{len(scans)} images" if len(scanned) < len(scans) else ""
    return f"{vulns} ({critical} crit{partial})"


def _rows(section: dict[str, Any]) -> list[tuple[int, list[str]]]:
    rows = []
    for inventory in section.get("inventories") or []:
        grants = _grants_by_account(inventory)
        for workload in inventory.get("workloads") or []:
            scans = [c.get("scan") or {} for c in workload.get("containers") or []]
            vulns = sum(int(s.get("vulnerabilities") or 0) for s in scans)
            account = (workload["namespace"], workload["service_account"])
            token = "" if workload.get("token_mounted") else ", no token"
            rows.append(
                (
                    vulns,
                    [
                        f"{workload['namespace']}/{workload['kind'].lower()}/{workload['name']}",
                        _cve_label(scans),
                        f"{workload['service_account']} ({_rbac_label(grants.get(account, []))}{token})",
                        str(len(workload.get("secret_refs") or [])),
                    ],
                )
            )
    return sorted(rows, key=lambda row: (-row[0], row[1][0]))


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
    table.add_column("Workload", overflow="fold")
    table.add_column("CVEs", no_wrap=True)
    table.add_column("Runs as", overflow="fold")
    table.add_column("Secrets", justify="right")
    for _vulns, cells in rows[:_ROWS]:
        table.add_row(*cells)
    con.print(table)
    if len(rows) > _ROWS:
        shown = f"Showing {_ROWS} of {len(rows)} workloads, most vulnerable first"
        con.print(f"  [dim]{shown}; full list in -f json (kubernetes_inventory).[/dim]")
