"""Whether a scan proves a cloud asset is gone.

An asset counts as deleted only when a complete inventory covered its exact
account, region and service and did not contain it. Coverage comes from the
collector's own receipt: the regions it walked, the API permissions it used, and
no warnings or missing permissions. AWS is the only source recording all of that;
any other source proves nothing here. Absence is checked against every string in
the inventory, so an asset a row names by id or name instead of ARN still counts
as present.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from agent_bom.evidence.cloud_scan import _status
from agent_bom.evidence.scan_run import ScanScopeStatus

_GLOBAL_SERVICES = frozenset({"s3", "iam", "cloudfront"})
_META_KEYS = frozenset({"provider", "status", "account_id", "region", "regions", "warnings", "missing_permissions", "discovery_envelope"})
_ACCOUNT_PREFIX = "aws:"


@dataclass(slots=True)
class DeletionProof:
    """The account, region and service combinations an inventory fully walked, and what it found."""

    covered: set[str] = field(default_factory=set)
    present: set[str] = field(default_factory=set)


def _digest(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def _coverage_key(account: str, region: str, service: str) -> str:
    return _digest("aws", account, region, service)


def _resource_name(value: str) -> str:
    """An ARN's final resource segment; any other string as it stands."""
    if not value.startswith("arn:"):
        return value
    resource = value.split(":", 5)[-1]
    return resource.rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def asset_location(row: dict[str, Any]) -> tuple[str | None, str | None]:
    """Opaque ``(asset, coverage)`` keys for a row on an ARN-named asset; ``None`` when it cannot be placed."""
    asset = row.get("asset")
    identifier = asset.get("identifier") if isinstance(asset, dict) else None
    if not isinstance(identifier, str) or not identifier.startswith("arn:"):
        return None, None
    parts = identifier.split(":", 5)
    if len(parts) < 6 or not parts[2] or not parts[5]:
        return None, None
    account = parts[4]
    if not account:
        reference = str(row.get("account_ref") or "")
        account = reference[len(_ACCOUNT_PREFIX) :] if reference.startswith(_ACCOUNT_PREFIX) else ""
    if not account:
        return None, None
    return _digest(_resource_name(identifier)), _coverage_key(account, parts[3], parts[2])


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _covered_by(member: dict[str, Any]) -> set[str]:
    account = member.get("account_id")
    envelope = member.get("discovery_envelope")
    permissions = envelope.get("permissions_used") if isinstance(envelope, dict) else None
    if not isinstance(account, str) or not account or not isinstance(permissions, list):
        return set()
    if _status(member, inventory=True) is not ScanScopeStatus.COMPLETE:
        return set()
    listed = member.get("regions")
    regions = [str(item) for item in listed] if isinstance(listed, list) else [str(member.get("region") or "")]
    services = {str(item).split(":", 1)[0] for item in permissions if isinstance(item, str) and ":" in item}
    covered: set[str] = set()
    for service in services:
        if service in _GLOBAL_SERVICES:
            covered.add(_coverage_key(account, "", service))
        else:
            covered.update(_coverage_key(account, region, service) for region in regions if region and not region.startswith("multi:"))
    return covered


def deletion_proof(result: dict[str, Any]) -> DeletionProof | None:
    """``None`` when the report carries no AWS inventory at all."""
    raw = result.get("cloud_inventory")
    members = [item for item in (raw if isinstance(raw, list) else [raw]) if isinstance(item, dict) and item.get("provider") == "aws"]
    if not members:
        return None
    proof = DeletionProof()
    for member in members:
        proof.covered |= _covered_by(member)
        for key, value in member.items():
            if key not in _META_KEYS:
                proof.present.update(_digest(_resource_name(text)) for text in _strings(value))
    return proof
