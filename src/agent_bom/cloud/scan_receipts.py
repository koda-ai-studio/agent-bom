"""Derive conservative capability receipts from observed scan summaries.

A finished job is not evidence that every service was readable. A receipt
names only a completed collection surface, never effective authorization or
managed AI discovery that was not performed by the connection runner.
"""

from __future__ import annotations

from typing import Any

_CONNECTION_PROVIDERS = frozenset({"aws", "azure", "gcp", "snowflake", "database", "databricks"})


def _complete_inventory(value: object) -> bool:
    if not isinstance(value, dict) or value.get("status") != "ok" or value.get("warnings"):
        return False
    if value.get("missing_permissions"):
        return False
    if "accounts" not in value:
        return "account_count" not in value
    accounts = value["accounts"]
    if not isinstance(accounts, list) or not accounts or value.get("account_count") != len(accounts):
        return False
    return all(
        isinstance(account, dict)
        and account.get("status") == "ok"
        and not account.get("warnings")
        and not account.get("missing_permissions")
        for account in accounts
    )


def _complete_benchmark(value: object) -> bool:
    if not isinstance(value, dict) or value.get("completeness") != "complete" or value.get("errored") != 0:
        return False
    evaluated, total = value.get("evaluated"), value.get("total")
    return type(evaluated) is int and type(total) is int and evaluated > 0 and evaluated == total


def scan_verified_capabilities(provider: str, *, summary: dict[str, Any] | None = None) -> tuple[str, ...]:
    """List only surfaces proved by this scan; absent or partial evidence verifies nothing."""
    if provider not in _CONNECTION_PROVIDERS or not isinstance(summary, dict):
        return ()
    capabilities: list[str] = []
    if _complete_inventory(summary.get("inventory")):
        capabilities.append(f"{provider}:inventory")
    if provider in {"aws", "azure", "gcp"} and _complete_benchmark(summary.get("cis_benchmark")):
        capabilities.append(f"{provider}:cis-read")
    return tuple(capabilities)
