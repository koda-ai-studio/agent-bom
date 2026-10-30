"""Project-scoped scan activation into the local control plane."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from uuid import uuid4

import click

from agent_bom.cli import _quickstart as quickstart
from agent_bom.cli._tenant import resolve_cli_tenant_id_strict
from agent_bom.storage import state_home


def _outside_project(path: Path, project: Path) -> None:
    if path.is_relative_to(project):
        raise click.ClickException("Evidence, state and database paths must be outside the selected project; project files are read-only.")


def _scan_args(executable: str, project: Path, report: Path, offline: bool) -> list[str]:
    # Reuse the explicit-project collector. --no-discover suppresses ambient
    # machine discovery while preserving this project's own MCP configurations.
    args = [executable, "agents", "-p", str(project), "--no-discover", "--context-graph", "--exit-zero", "-f", "json", "-o", str(report)]
    if offline:
        args.extend(["--offline", "--no-scan"])
    return args


def _plan(project: Path, evidence_dir: Path, offline: bool, port: int) -> None:
    click.echo("Project-scoped onboarding: manifests, lockfiles and project MCP configuration; ambient discovery is disabled.")
    click.echo("Project files stay read-only. Each run retains a separate report, graph snapshot and activation receipt.")
    click.echo(
        "Offline skips package-CVE lookup; inventory is not a clean security verdict."
        if offline
        else "Uses the scan's standard advisory lookup services; review coverage_warnings before interpreting findings."
    )
    command = ["agent-bom", "quickstart", "--project", str(project), "--evidence-dir", str(evidence_dir), "--port", str(port), "--run"]
    if offline:
        command.append("--offline")
    click.echo("Run:")
    click.echo("  " + shlex.join(command))


def activate_project(*, project: Path, evidence_dir: Path | None, offline: bool, execute: bool, port: int) -> None:
    try:
        resolve_cli_tenant_id_strict()
    except (RuntimeError, ValueError):
        raise click.ClickException(
            "Project activation requires a valid explicit tenant for a shared deployment; set AGENT_BOM_TENANT_ID."
        ) from None
    project = project.resolve()
    destination = (evidence_dir or state_home.state_path("activations") / str(uuid4())).expanduser().resolve()
    environment = os.environ.copy()
    control_db, graph_db = quickstart._resolve_quickstart_databases(environment)
    for path in (destination, control_db, graph_db, state_home.state_dir().expanduser().resolve()):
        _outside_project(path, project)
    if destination.exists():
        raise click.ClickException("Evidence directory already exists; select a new directory to retain previous runs unchanged.")
    _plan(project, destination, offline, port)
    if not execute:
        return
    executable = quickstart._resolve_agent_bom()
    if executable is None:
        raise click.ClickException("The agent-bom executable is unavailable; activate the environment where it is installed.")
    if importlib.util.find_spec("fastapi") is None:
        raise click.ClickException("Install dashboard dependencies first: pip install 'agent-bom[ui]'")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.mkdir(mode=0o700)
    except OSError:
        raise click.ClickException("Cannot create a new private evidence directory. Existing files are retained.") from None
    report = destination / "report.json"
    environment.update(AGENT_BOM_DB=str(control_db), AGENT_BOM_GRAPH_DB=str(graph_db))
    started = datetime.now(timezone.utc)
    click.echo(f"Evidence directory: {destination}")
    try:
        result = quickstart.subprocess.run(
            _scan_args(executable, project, report, offline),
            check=False,
            env=environment,
            timeout=quickstart.QUICKSTART_SCAN_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise click.ClickException(
            "Project scan did not complete. Retained evidence is incomplete; no activation receipt was issued."
        ) from None
    if result.returncode != 0:
        raise click.ClickException(
            f"Project scan exited with status {result.returncode}. Retained evidence is incomplete; no activation receipt was issued."
        )
    graph = quickstart._verify_persisted_graph(report_path=report, graph_db=graph_db, scan_started_at=started)
    quickstart._persist_completed_scan(report, control_db, graph["scan_id"], started)
    _receipt_and_handoff(project, destination, report, graph, control_db, graph_db, offline, port)


def _receipt_and_handoff(
    project: Path,
    destination: Path,
    report: Path,
    graph: quickstart._GraphReceipt,
    control_db: Path,
    graph_db: Path,
    offline: bool,
    port: int,
) -> None:
    tenant = resolve_cli_tenant_id_strict()
    base = f"http://127.0.0.1:{port}"
    query = urlencode({"scan": graph["scan_id"]})
    links = {"findings": f"{base}/findings?{query}", "investigation": f"{base}/security-graph?{query}"}
    receipt = {
        "schema_version": "project-activation.v1",
        "tenant_id": tenant,
        "project": str(project),
        "report": str(report),
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "graph": graph,
        "control_plane_db": str(control_db),
        "graph_db": str(graph_db),
        "package_cve_lookup": "skipped" if offline else "requested",
        "links": links,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with os.fdopen(os.open(destination / "activation.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
    except OSError:
        raise click.ClickException("Scan and graph were retained, but the activation receipt could not be written.") from None
    click.echo("\nProject activation complete. The exact scan and graph were read back from the configured local databases.")
    click.echo(f"JSON report: {report}")
    click.echo(f"Activation receipt: {destination / 'activation.json'}")
    click.echo(
        f"Graph: {graph['nodes']} nodes, {graph['edges']} relationships. These counts do not prove exploitability or complete collection."
    )
    click.echo("Review scan_run and coverage_warnings in the report. This local receipt is not independent remediation verification.")
    click.echo("Start the dashboard in the same Python environment (install agent-bom[ui] if needed):")
    click.echo(
        "  "
        + quickstart._control_plane_command(control_plane_db=control_db, graph_db=graph_db, port=port, local_analyst=tenant == "default")
    )
    if tenant == "default":
        click.echo("  # Loopback analyst mode; use --api-key <key> or OIDC on a shared host.")
    else:
        click.echo(f"  # Configure an authenticated API-key/OIDC principal for tenant {shlex.quote(tenant)} before opening these links.")
        click.echo("  # Anonymous mode and a static --api-key use the default tenant, so they cannot read this scan.")
    click.echo("Findings: " + links["findings"])
    click.echo("Investigation: " + links["investigation"])
    click.echo("After a change, rerun quickstart --project with a new evidence directory; compare scoped scans before claiming a fix.")
