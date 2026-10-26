"""``agent-bom cloud side-scan`` and ``side-scan-capabilities``.

The side-scan is the one opt-in mutation family (temp snapshot / disk create,
attach and delete); its output is metadata only: package SBOM, CVEs per VM,
and secret type/location.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional, cast

import click

from agent_bom.cli._tenant import resolve_cli_tenant_id

if TYPE_CHECKING:  # pragma: no cover - typing only
    from rich.console import Console

    from agent_bom.cloud.side_scan import SideScanResult


@click.command("side-scan")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    default="aws",
    show_default=True,
    help="Cloud provider. AWS EBS, Azure Managed Disk, and GCP Persistent Disk all ship a CLI executor.",
)
@click.option(
    "--instance-id",
    default=None,
    help="AWS only: EC2 instance whose attached EBS volumes to scan.",
)
@click.option(
    "--volume-id",
    default=None,
    help="Target disk to scan. AWS: EBS volume id. Azure/GCP: the managed/persistent disk resource id.",
)
@click.option(
    "--collector-instance-id",
    default=None,
    help="In-account collector instance/VM the temp disk is attached to (no block data leaves the account).",
)
@click.option(
    "--availability-zone",
    default=None,
    help="Location for the temp disk (must match the collector). AWS AZ / Azure location / GCP zone.",
)
@click.option("--region", default=None, help="AWS region (AWS only).")
@click.option(
    "--account-id",
    default=None,
    help="Azure subscription id / GCP project id that owns the disk and collector (Azure/GCP only).",
)
@click.option(
    "--collector-resource-group",
    default=None,
    help="Azure only: resource group of the in-account collector VM.",
)
@click.option(
    "--tenant-id",
    default=None,
    help="Tenant that owns the durable lifecycle state (Azure/GCP). Defaults to $AGENT_BOM_TENANT_ID or 'default'.",
)
@click.option(
    "--image-id",
    default=None,
    help="Scan a machine image instead of a disk. AWS: AMI id (temp volume from its root snapshot). "
    "GCP: image resource path. Azure managed images are not supported.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    show_default=True,
    help="console tables, or JSON side_scan_results records (packages + CVEs per VM / image).",
)
@click.option("--no-secrets", is_flag=True, help="Skip the redacted secret scan (SBOM + CVEs only).")
@click.option("--no-sweep-orphans", is_flag=True, help="AWS only: skip the pre-run sweep of stranded snapshots.")
def side_scan_cmd(
    provider: str,
    instance_id: Optional[str],
    volume_id: Optional[str],
    collector_instance_id: Optional[str],
    availability_zone: Optional[str],
    region: Optional[str],
    account_id: Optional[str],
    collector_resource_group: Optional[str],
    tenant_id: Optional[str],
    image_id: Optional[str],
    output_format: str,
    no_secrets: bool,
    no_sweep_orphans: bool,
) -> None:
    """Agentless disk / machine-image side-scan — SBOM + CVEs per VM + redacted secrets.

    Each provider takes a snapshot of the target disk, creates a temp disk from
    it, attaches that to an *in-account collector* instance, mounts it read-only,
    parses the package SBOM + secret type/location (never values, never file
    contents), and tears everything down in a guaranteed cleanup. No disk image
    or block data ever leaves the account. This is an opt-in mutation family
    (temp snapshot/disk create, attach, delete) — not a read-only scan.

    Packages and CVEs are reported per owning VM (AWS volume attachment, Azure
    disk ``managed_by``, GCE disk ``users``) and carry into the graph as
    VM -> package -> CVE. ``--image-id`` scans an AWS AMI (temp volume from its
    root snapshot, the AMI is never modified) or a GCE image (temp disk from the
    image); Azure managed images are not supported.

    AWS EBS, Azure Managed Disk, and GCP Persistent Disk all ship a CLI executor.
    Credentials are never embedded — the Azure/GCP executors resolve separately
    scoped lifecycle credentials from the provider's default chain, and no live-cloud smoke is
    claimed yet (``credentialed_smoke=false``). Use
    ``agent-bom cloud side-scan-capabilities`` and cloud inventory
    ``side_scan_targets`` for the honest surface.

    Requires the scoped snapshot role and an in-account collector instance. Gated
    by ``AGENT_BOM_SIDESCAN`` — OFF by default; an unset flag prints how to enable
    it and exits non-zero.

    \b
    Examples:
      AGENT_BOM_SIDESCAN=1 agent-bom cloud side-scan \\
        --volume-id vol-0abc --collector-instance-id i-0def \\
        --availability-zone us-east-1a --region us-east-1
      AGENT_BOM_SIDESCAN=1 agent-bom cloud side-scan --provider azure \\
        --volume-id /subscriptions/SUB/resourceGroups/RG/providers/Microsoft.Compute/disks/os \\
        --account-id SUB --collector-instance-id collector-vm \\
        --collector-resource-group collectors --availability-zone eastus
      AGENT_BOM_SIDESCAN=1 agent-bom cloud side-scan --provider gcp \\
        --volume-id projects/PROJ/zones/us-central1-a/disks/os --account-id PROJ \\
        --collector-instance-id collector-vm --availability-zone us-central1-a
      AGENT_BOM_SIDESCAN=1 agent-bom cloud side-scan --image-id ami-0abc \\
        --collector-instance-id i-0def --availability-zone us-east-1a -f json
      agent-bom cloud side-scan-capabilities -f json
    """
    import asyncio

    from rich.console import Console

    from agent_bom.cloud.base import CloudDiscoveryError
    from agent_bom.cloud.side_scan import run_side_scan
    from agent_bom.cloud.side_scan_inventory import side_scan_record
    from agent_bom.cloud.side_scan_lifecycle import (
        SideScanProvider,
        side_scan_provider_capabilities,
    )
    from agent_bom.cloud.side_scan_targets import AZURE_IMAGE_UNSUPPORTED, run_provider_side_scan

    con = Console()
    provider_key = cast(SideScanProvider, provider.strip().lower())
    capabilities = side_scan_provider_capabilities()
    capability = capabilities.get(provider_key)
    if capability is None or not capability.cli_available:
        executor = capability.executor if capability is not None else "unknown"
        con.print(f"\n  [yellow]side-scan executor unavailable for {provider_key}:[/yellow] executor={executor}, cli_available=false")
        con.print("  [dim]See `agent-bom cloud side-scan-capabilities` and inventory `side_scan_targets`.[/dim]\n")
        raise SystemExit(2)
    if image_id and provider_key == "azure":
        con.print(f"\n  [yellow]side-scan unavailable:[/yellow] {AZURE_IMAGE_UNSUPPORTED}\n")
        raise SystemExit(2)
    as_json = output_format.lower() == "json"

    try:
        if provider_key == "aws":
            results = asyncio.run(
                run_side_scan(
                    instance_id=instance_id,
                    volume_id=volume_id,
                    image_id=image_id,
                    collector_instance_id=collector_instance_id,
                    availability_zone=availability_zone,
                    region=region,
                    scan_secrets_enabled=not no_secrets,
                    sweep_orphans=not no_sweep_orphans,
                )
            )
            records = [side_scan_record(result, provider="aws") for result in results]
            if not as_json:
                _render_side_scan_results(con, results)
        else:
            provider_results = asyncio.run(
                run_provider_side_scan(
                    provider=provider_key,
                    target_id=image_id or volume_id or "",
                    target_type="image" if image_id else "disk",
                    account_id=account_id or "",
                    location=availability_zone or "",
                    collector_id=collector_instance_id or "",
                    tenant_id=resolve_cli_tenant_id(tenant_id),
                    collector_resource_group=collector_resource_group,
                    region=region,
                    scan_secrets_enabled=not no_secrets,
                )
            )
            records = [side_scan_record(result, provider=provider_key) for result in provider_results]
            if not as_json:
                _render_provider_side_scan_results(con, provider_key, provider_results)
    except CloudDiscoveryError as exc:
        # Actionable, user-safe opt-in / config guidance authored in the side-scan
        # module — no exception internals, safe to surface directly.
        con.print(f"\n  [yellow]side-scan unavailable:[/yellow] {exc}\n")
        raise SystemExit(1) from None
    except Exception as exc:  # noqa: BLE001 - never leak a raw traceback for a provider fault
        from agent_bom.security import sanitize_text

        con.print(f"\n  [red]side-scan failed for {provider_key}:[/red] [dim]{sanitize_text(exc)}[/dim]")
        con.print(
            "  [dim]Inspect execution history and owned resources for cleanup state; "
            "a new scan does not resume an earlier teardown.[/dim]\n"
        )
        raise SystemExit(1) from None
    if as_json:
        click.echo(json.dumps({"side_scan_results": records}, indent=2, sort_keys=True))
        return
    _render_vulnerable_packages(con, records)


_CONSOLE_CVE_ROWS = 25


def _render_vulnerable_packages(con: Console, records: list[dict]) -> None:
    """Vulnerable packages per VM / image — the same records the JSON report and graph carry."""
    from rich.table import Table

    for record in records:
        holder = record.get("instance_name") or record.get("instance_id") or record.get("target_id") or "unknown"
        rows = [(pkg, vuln) for pkg in record.get("packages", []) for vuln in pkg.get("vulnerabilities", [])]
        if not rows:
            continue
        total, vulnerable = record.get("vulnerability_count", 0), record.get("vulnerable_package_count", 0)
        table = Table(title=f"CVEs · {holder} [dim]({total} across {vulnerable} package(s))[/dim]")
        table.add_column("CVE")
        table.add_column("Severity")
        table.add_column("Package", overflow="fold")
        table.add_column("Fixed in", overflow="fold")
        for pkg, vuln in rows[:_CONSOLE_CVE_ROWS]:
            table.add_row(
                str(vuln.get("id")),
                str(vuln.get("severity") or "unknown"),
                f"{pkg.get('name')}@{pkg.get('version')}",
                str(vuln.get("fixed_version") or "—"),
            )
        con.print(table)
        if len(rows) > _CONSOLE_CVE_ROWS or record.get("packages_truncated"):
            shown = min(len(rows), _CONSOLE_CVE_ROWS)
            con.print(f"  [dim]Showing {shown} of {total} CVE(s); use -f json for the full bounded list.[/dim]")


@click.command("side-scan-capabilities")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
def side_scan_capabilities_cmd(output_format: str) -> None:
    """Print honest CWPP side-scan provider capabilities (no cloud mutations).

    AWS is the shipped CLI executor. Azure/GCP advertise target discovery and a
    lifecycle contract only until credentialed smoke proves otherwise.
    """

    from rich.console import Console
    from rich.table import Table

    from agent_bom.cloud.side_scan_lifecycle import side_scan_provider_capabilities

    capabilities = [cap.to_dict() for cap in side_scan_provider_capabilities().values()]
    con = Console()
    if output_format.lower() == "json":
        con.print_json(json.dumps(capabilities, sort_keys=True))
        return

    table = Table(title="CWPP side-scan capabilities")
    table.add_column("Provider")
    table.add_column("Target discovery")
    table.add_column("Lifecycle contract")
    table.add_column("Executor")
    table.add_column("CLI")
    table.add_column("Credentialed smoke")
    table.add_column("Images")
    for row in capabilities:
        table.add_row(
            str(row.get("provider") or ""),
            "yes" if row.get("target_discovery") else "no",
            "yes" if row.get("lifecycle_contract") else "no",
            str(row.get("executor") or ""),
            "yes" if row.get("cli_available") else "no",
            "yes" if row.get("credentialed_smoke") else "no",
            str(row.get("image_scan") or "unsupported"),
        )
    con.print(table)
    con.print(
        "\n  [dim]AWS EBS, Azure Managed Disk, and GCP Persistent Disk all ship a CLI executor. "
        "No live credentialed smoke is claimed for any provider yet (credentialed_smoke=false).[/dim]\n"
    )


def _render_side_scan_results(con: Console, results: list[SideScanResult]) -> None:
    """Render side-scan results in Rich tables — metadata only, no overflow."""
    from rich.table import Table

    con.print("\n  [bold]EBS side-scan[/bold] [dim]· agentless · opt-in temp disks · metadata-only · cleanup recorded[/dim]")

    if not results:
        con.print("  [yellow]No target volumes resolved.[/yellow] [dim]Pass --volume-id or --instance-id.[/dim]\n")
        return

    summary = Table()
    summary.add_column("Volume")
    summary.add_column("Instance")
    summary.add_column("Snapshot")
    summary.add_column("Packages", justify="right")
    summary.add_column("Vuln pkgs", justify="right")
    summary.add_column("Secrets", justify="right")
    summary.add_column("Cleaned up")
    for res in results:
        summary.add_row(
            str(res.volume_id or "—"),
            str(res.instance_id or "—"),
            str(res.snapshot_id or "—"),
            str(len(res.packages)),
            str(res.vulnerability_count),
            str(len(res.secrets)),
            "[green]yes[/green]" if res.cleaned_up else "[yellow]partial[/yellow]",
        )
    con.print(summary)

    for res in results:
        if not res.cleaned_up and res.scan_volume_id:
            con.print(f"  [yellow]Retained scan volume:[/yellow] {res.scan_volume_id} · snapshot {res.snapshot_id or 'unknown'}")
        if res.secrets:
            secrets = Table(title=f"Secrets · {res.volume_id} [dim](type + location only)[/dim]")
            secrets.add_column("Type")
            secrets.add_column("File", overflow="fold")
            secrets.add_column("Line", justify="right")
            secrets.add_column("Severity")
            for sec in res.secrets:
                secrets.add_row(sec.secret_type, sec.file_path, str(sec.line_number), sec.severity)
            con.print(secrets)
        for warning in res.warnings:
            con.print(f"  [yellow]![/yellow] [dim]{warning}[/dim]")
    con.print()


def _render_provider_side_scan_results(con: Console, provider: str, results: list) -> None:
    """Render Azure/GCP side-scan results — metadata only, cleanup + warnings honest."""
    from rich.table import Table

    label = "Azure Managed Disk" if provider == "azure" else "GCP Persistent Disk"
    con.print(f"\n  [bold]{label} side-scan[/bold] [dim]· agentless · opt-in temp disks · metadata-only · cleanup recorded[/dim]")

    if not results:
        con.print("  [yellow]No target disks resolved.[/yellow] [dim]Pass --volume-id (disk resource id).[/dim]\n")
        return

    summary = Table()
    summary.add_column("Execution")
    summary.add_column("Status")
    summary.add_column("Disk")
    summary.add_column("Snapshot")
    summary.add_column("Scan disk")
    summary.add_column("Packages", justify="right")
    summary.add_column("Vuln pkgs", justify="right")
    summary.add_column("Secrets", justify="right")
    summary.add_column("Cleanup")
    for res in results:
        execution_status = str(res.execution_status or "unknown").replace("_", " ")
        cleanup_status = str(res.cleanup_status or ("complete" if res.cleaned_up else "partial")).replace("_", " ")
        counts = res.to_dict()
        summary.add_row(
            str(res.execution_id or "—"),
            execution_status,
            str(res.target_id or "—"),
            str(res.snapshot_id or "—"),
            str(res.scan_disk_id or "—"),
            str(counts["package_count"]),
            str(counts["vulnerability_count"]),
            str(counts["secret_count"]),
            f"[green]{cleanup_status}[/green]" if res.cleaned_up else f"[yellow]{cleanup_status}[/yellow]",
        )
    con.print(summary)

    for res in results:
        if res.secrets:
            secrets = Table(title=f"Secrets · {res.target_id} [dim](type + location only)[/dim]")
            secrets.add_column("Type")
            secrets.add_column("File", overflow="fold")
            secrets.add_column("Line", justify="right")
            secrets.add_column("Severity")
            for sec in res.secrets:
                secrets.add_row(sec.secret_type, sec.file_path, str(sec.line_number), sec.severity)
            con.print(secrets)
        for warning in res.warnings:
            con.print(f"  [yellow]![/yellow] [dim]{warning}[/dim]")
    con.print("  [dim]Zero findings are scoped to the scanned disk only — never a clean-workload assertion.[/dim]\n")
