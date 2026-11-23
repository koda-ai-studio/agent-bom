#!/usr/bin/env python3
"""Source-checkout wrapper for ``agent-bom auth mint-admin-key``.

The bootstrap lives in the package (``agent_bom.api.admin_key_bootstrap``) so it
ships in every runtime image; prefer the CLI command inside the API container.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_bom.api.admin_key_bootstrap import (
    MintedAdminKey,
    bootstrap_admin_key,
    failure_message,
    mint_admin_key,
    write_raw_key_file,
)

DEFAULT_RAW_KEY_FILE = Path("/tmp/agent-bom-customer0-admin.key")

__all__ = ["DEFAULT_RAW_KEY_FILE", "MintedAdminKey", "main", "mint_admin_key", "write_raw_key_file"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mint an initial hosted admin API key (same as `agent-bom auth mint-admin-key`)")
    parser.add_argument("--tenant-id", default="customer-0", help="tenant id for the invited account")
    parser.add_argument("--name", default="customer-0-admin", help="display name stored for the key")
    parser.add_argument("--expires-at", default=None, help="optional ISO-8601 expiration")
    parser.add_argument("--scope", action="append", dest="scopes", help="scope to add; defaults to '*'")
    parser.add_argument("--allow-inmemory", action="store_true", help="allow local in-memory bootstrap for tests only")
    parser.add_argument(
        "--raw-key-file", type=Path, default=DEFAULT_RAW_KEY_FILE, help="private 0600 file that receives the one-time raw API key"
    )
    parser.add_argument("--force", action="store_true", help="overwrite --raw-key-file if it already exists")
    args = parser.parse_args(argv)
    try:
        payload = bootstrap_admin_key(
            tenant_id=args.tenant_id,
            name=args.name,
            raw_key_file=args.raw_key_file,
            expires_at=args.expires_at,
            scopes=args.scopes,
            allow_inmemory=args.allow_inmemory,
            force=args.force,
        )
    except Exception as exc:  # noqa: BLE001 - CLI entrypoint returns a clean failure
        print(failure_message(exc), file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"raw API key written once to {payload['raw_key_file']} with mode 0600", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
