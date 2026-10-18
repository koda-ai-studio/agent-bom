"""Explicit, read-only Supabase inventory and native-advisor command."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from uuid import uuid4

import click

from agent_bom.cli._tenant import resolve_cli_tenant_id_strict
from agent_bom.security import sanitize_error


def _write_report(path: Path, report: dict) -> None:
    """Publish the complete normalized artifact atomically, with private mode."""
    report["evidence_sha256"] = hashlib.sha256(
        json.dumps({key: value for key, value in report.items() if key != "evidence_sha256"}, sort_keys=True).encode()
    ).hexdigest()
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".supabase-", delete=False) as stream:
            temporary = stream.name
            json.dump(report, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def _persist_report(report: dict, graph_db: Path, tenant_id: str, output: Path) -> None:
    """Persist one stable project scope and publish the actual storage outcome."""
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph
    from agent_bom.graph.builder import build_unified_graph_from_report

    try:
        graph_db.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(graph_db, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        if os.name != "nt" and graph_db.stat().st_mode & 0o077:
            raise ValueError("Graph database must be private (chmod 600)")
        for receipt in report["coverage"]:
            receipt["persisted"] = True
            receipt["correlated"] = receipt["capability"] == "security_advisors" and any(
                finding["evidence"]["project_ref"] == receipt["project_ref"] for finding in report["findings"]
            )
        graph = build_unified_graph_from_report(report, scan_id=report["scan_id"], tenant_id=tenant_id)
        with open_graph_db(graph_db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = load_graph(conn, tenant_id=tenant_id, entity_types={"cloud_resource"})
            expected = {node.id for node in graph.nodes.values() if node.attributes.get("project_ref")}
            if previous.scan_id and set(previous.nodes) != expected:
                raise ValueError("Project scope changed; use a separate graph database")
            save_graph(conn, graph)
    except Exception:
        for receipt in report["coverage"]:
            receipt["persisted"] = False
            receipt["correlated"] = False
        report["persistence"] = {"graph": "failed"}
        _write_report(output, report)
        raise
    report["persistence"] = {"graph": "persisted", "tenant_id": tenant_id, "scan_id": graph.scan_id}
    _write_report(output, report)


@click.command("supabase")
@click.option("--project-ref", "project_refs", multiple=True, required=True, help="Explicit project ref; repeat for each approved project.")
@click.option(
    "--token-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Private JSON file containing a token field. Requires project_admin_read and advisors_read.",
)
@click.option(
    "--output", type=click.Path(dir_okay=False, path_type=Path), required=True, help="Normalized JSON report and capability receipts."
)
@click.option("--graph-db", type=click.Path(dir_okay=False, path_type=Path), help="Optional dedicated SQLite graph snapshot database.")
@click.option("--tenant", default=None, help="Tenant for graph persistence; uses the standard CLI tenant resolution.")
def supabase_cmd(project_refs: tuple[str, ...], token_file: Path, output: Path, graph_db: Path | None, tenant: str | None) -> None:
    """Read scoped Supabase project metadata and native security advisors.

    Never resumes projects, queries data, executes advisors or reads API keys.
    Exit 2 retains a partial report but leaves the previous graph snapshot intact.
    Use a dedicated graph database for this scoped inventory, not a fleet scan DB.
    """
    from agent_bom.cloud.supabase_inventory import collect_report

    try:
        if token_file.stat().st_size > 65536:
            raise ValueError("Token file is too large")
        if os.name != "nt" and token_file.stat().st_mode & 0o077:
            raise ValueError("Token file must be private (chmod 600)")
        credential = json.loads(token_file.read_text())
        if not isinstance(credential, dict):
            raise ValueError("Token file must contain a token field")
        token = credential.get("token")
        if not isinstance(token, str):
            raise ValueError("Token file must contain a token string")
        if output.resolve() == token_file.resolve() or (
            graph_db is not None and (output.resolve() == graph_db.resolve() or graph_db.resolve() == token_file.resolve())
        ):
            raise ValueError("Report output must differ from credential and graph files")
        tenant_id = resolve_cli_tenant_id_strict(tenant)
        report = collect_report(project_refs=list(project_refs), token=token)
        report["scan_id"] = str(uuid4())
        report["persistence"] = {"graph": "not_requested"}
        # Persist the receipt first, including failures. Failed collection must
        # not publish a replacement snapshot that can hide previously seen assets.
        if graph_db is not None:
            report["persistence"]["graph"] = "skipped_incomplete" if report["status"] != "ok" else "pending"
        _write_report(output, report)
        if graph_db is not None and report["status"] == "ok":
            _persist_report(report, graph_db, tenant_id, output)
    except Exception as exc:
        raise click.ClickException(sanitize_error(exc, generic=True)) from exc
    click.echo(f"Supabase: {report['status']}; {len(report['cloud_inventory'])} projects; {len(report['findings'])} native findings.")
    click.echo(f"Report: {output}. Empty advisors do not establish clean posture.")
    if report["status"] != "ok":
        raise click.exceptions.Exit(2)
