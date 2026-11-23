"""``agent-bom auth mint-admin-key`` — first admin key of a self-hosted control plane.

Shipped in the package so it exists in every runtime image; run it inside the
API container so the record lands in the store the API reads.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click


@click.command("mint-admin-key")
@click.option("--tenant-id", default="customer-0", show_default=True, help="Tenant the admin key belongs to.")
@click.option("--name", default="customer-0-admin", show_default=True, help="Display name stored for the key.")
@click.option("--expires-at", default=None, help="Optional ISO-8601 expiration.")
@click.option("--scope", "scopes", multiple=True, help="Scope to grant (repeatable); defaults to '*'.")
@click.option(
    "--raw-key-file",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Private 0600 file that receives the one-time raw API key; refuses to overwrite unless --force.",
)
@click.option("--force", is_flag=True, help="Overwrite --raw-key-file if it already exists.")
@click.option("--allow-inmemory", is_flag=True, hidden=True, help="Local tests only: allow an in-memory key store.")
def mint_admin_key_cmd(
    tenant_id: str,
    name: str,
    expires_at: Optional[str],
    scopes: tuple[str, ...],
    raw_key_file: Path,
    force: bool,
    allow_inmemory: bool,
) -> None:
    """Mint the first admin API key into the persistent key store.

    Prints non-secret metadata as JSON; the raw key is written once to
    --raw-key-file with mode 0600 and never printed.
    """
    from agent_bom.api.admin_key_bootstrap import bootstrap_admin_key, failure_message

    try:
        payload = bootstrap_admin_key(
            tenant_id=tenant_id,
            name=name,
            raw_key_file=raw_key_file,
            expires_at=expires_at,
            scopes=list(scopes) or None,
            allow_inmemory=allow_inmemory,
            force=force,
        )
    except Exception as exc:  # noqa: BLE001 - CLI entrypoint returns a clean failure
        click.echo(failure_message(exc), err=True)
        sys.exit(1)
    click.echo(json.dumps(payload, indent=2, sort_keys=True))
    click.echo(f"raw API key written once to {payload['raw_key_file']} with mode 0600", err=True)
