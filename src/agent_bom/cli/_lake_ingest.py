"""Normalize explicit customer lake snapshots and optionally push the retained report."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click

from agent_bom.cli._lake_activation import emit_lake_push_receipt
from agent_bom.connectors.lake_snapshot import decode_lake_snapshot, read_lake_snapshot
from agent_bom.core.settings import env_opt
from agent_bom.parsers.lake_evidence import build_lake_report
from agent_bom.push import normalize_scan_push_url, push_json
from agent_bom.security import sanitize_text


@click.command("lake")
@click.argument("source")
@click.option("--mapping", "mapping_file", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--input-format", type=click.Choice(["json", "ndjson"]), default="json", show_default=True)
@click.option("--s3-version-id", help="Exact non-null object version; required for S3.")
@click.option("--s3-expected-owner", help="Expected bucket owner account; required for S3.")
@click.option("-o", "--output", "output_file", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--push", "push_url", help="Explicit control-plane URL; authenticates with AGENT_BOM_PUSH_API_KEY.")
def lake_cmd(
    source: str,
    mapping_file: Path,
    input_format: str,
    s3_version_id: str | None,
    s3_expected_owner: str | None,
    output_file: Path,
    push_url: str | None,
) -> None:
    """Map JSON/NDJSON finding snapshots from a local export or version-pinned S3 object.

    Unmapped fields are omitted. No SQL, bucket listing, event subscription or
    cloud scan runs. The report is retained before an optional authenticated push.
    """
    api_key = env_opt("AGENT_BOM_PUSH_API_KEY") if push_url else None
    if push_url and not api_key:
        raise click.ClickException("Set AGENT_BOM_PUSH_API_KEY before requesting a push.")
    try:
        config, _ = read_lake_snapshot(str(mapping_file))
        data, receipt = read_lake_snapshot(source, version_id=s3_version_id, expected_owner=s3_expected_owner)
        rows, digest = decode_lake_snapshot(data, input_format=input_format)
        report = build_lake_report(rows, json.loads(config), artifact_sha256=digest, object_receipt=receipt)
        payload = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    except (OSError, ValueError, TypeError, ImportError, RecursionError):
        raise click.ClickException("Cannot import lake snapshot; check mapping, row limits, timestamps and read permissions.") from None
    try:
        with os.fdopen(os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
            stream.write(payload)
    except OSError:
        raise click.ClickException("Cannot create report; choose a new writable artifact path.") from None
    click.echo(f"Retained finding observations: {len(report['findings'])}. Source collection coverage remains unknown.")
    click.echo("Report saved: " + sanitize_text(str(output_file.resolve()), max_len=2000))
    if push_url:
        response = push_json(
            normalize_scan_push_url(push_url), report, api_key, source_id=report["source_id"], idempotency_key=report["idempotency_key"]
        )
        if response is None:
            raise click.ClickException("Push failed. The local report is retained for retry.")
        emit_lake_push_receipt(response, push_url)
