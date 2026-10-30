"""Local sample setup and scoped handoffs for imported lake evidence."""

from __future__ import annotations

import json
import os
import shlex
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit

import click

from agent_bom.push import SCAN_PUSH_PATH, normalize_scan_push_url
from agent_bom.security import sanitize_text


@click.command("lake-sample")
@click.option("--directory", required=True, type=click.Path(path_type=Path), help="New private directory for synthetic sample files.")
def lake_sample_cmd(directory: Path) -> None:
    """Create a synthetic lake snapshot and mapping from the installed package.

    Use an isolated pilot control plane for this sample. Replace both inputs
    with customer-selected evidence before evaluating a real environment.
    """
    sample = json.loads(files("agent_bom.data").joinpath("lake_sample.json").read_text(encoding="utf-8"))
    try:
        directory.mkdir(mode=0o700)
        for name, content in (("findings.json", sample["findings"]), ("mapping.json", sample["mapping"])):
            with os.fdopen(os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
                json.dump(content, stream, indent=2)
                stream.write("\n")
    except OSError:
        raise click.ClickException(
            "Cannot create sample files; use a new directory with a writable parent. Existing files are retained."
        ) from None
    command = [
        "agent-bom",
        "ingest",
        "lake",
        str(directory / "findings.json"),
        "--mapping",
        str(directory / "mapping.json"),
        "-o",
        str(directory / "report.json"),
    ]
    click.echo("Synthetic sample: two labelled findings in the sample environment; no cloud access or collection occurs.")
    click.echo("Next: " + shlex.join(command))
    click.echo("To import into an isolated pilot, set AGENT_BOM_PUSH_API_KEY securely and append --push <control-plane-url>.")


def _dashboard_link(destination: str, route: str, scan_id: str) -> str | None:
    """Retain a deployment prefix, removing credentials and API-only URL parts."""
    try:
        parsed = urlsplit(normalize_scan_push_url(destination))
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.path.endswith(SCAN_PUSH_PATH):
        return None
    prefix = parsed.path.removesuffix(SCAN_PUSH_PATH)
    base = urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], prefix + route, "", ""))
    return sanitize_text(base, max_len=1500) + "?" + urlencode({"scan": sanitize_text(scan_id, max_len=200)})


def emit_lake_push_receipt(response: dict, destination: str) -> None:
    """Report storage and graph evidence independently; never infer missing proof."""
    job_id = response.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        click.echo("Storage receipt has no scan identifier; inspect the control plane before retrying the retained report.")
        return
    click.echo(f"Stored scan: {sanitize_text(job_id, max_len=100)}.")
    findings = _dashboard_link(destination, "/findings", job_id)
    if findings:
        click.echo("Findings: " + findings)
    graph = response.get("graph_persistence")
    if not isinstance(graph, dict) or graph.get("status") != "persisted":
        click.echo(
            "Graph evidence is not confirmed by this receipt. Inspect the stored scan; import alone does not prove graph persistence."
        )
        return
    nodes, edges = graph.get("nodes"), graph.get("edges")
    if type(nodes) is not int or type(edges) is not int or nodes <= 0 or edges <= 0:
        click.echo(
            "Graph evidence has no confirmed nonempty node-and-relationship counts. Inspect the stored scan before investigating paths."
        )
        return
    click.echo(f"Graph persisted: {nodes} nodes, {edges} relationships. This does not establish exploitability or complete collection.")
    scan_id = graph.get("scan_id")
    if isinstance(scan_id, str) and scan_id:
        link = _dashboard_link(destination, "/security-graph", scan_id)
        if link:
            click.echo("Investigation: " + link)
