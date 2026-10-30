"""Explicit, bounded lake finding mappings into the canonical scan-report contract."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, overload

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, TypeAdapter

from agent_bom.canonical_ids import canonical_finding_id
from agent_bom.domain.asset_identity import finding_asset_occurrence_id
from agent_bom.domain.finding_model import Asset, Finding
from agent_bom.domain.finding_types import ControlTag, FindingSource, FindingType
from agent_bom.finding_scope import normalize_account_ref

Text = Annotated[str, Field(strict=True, min_length=1, max_length=1024, pattern=r"^[^\x00-\x1f\x7f]+$")]
_TIMESTAMP = TypeAdapter(AwareDatetime)
_FIELDS = frozenset(
    {
        "finding_id",
        "asset_id",
        "asset_name",
        "title",
        "severity",
        "observed_at",
        "provider",
        "account_id",
        "region",
        "environment",
        "description",
        "remediation_guidance",
        "fixed_version",
        "cve_id",
        "controls",
    }
)


class LakeMapping(BaseModel):
    """Column names or JSON pointers, never executable expressions or SQL."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["agent-bom.lake-mapping/v1"]
    provider: Literal["aws-security-lake", "s3", "snowflake", "databricks", "bigquery", "clickhouse", "local"]
    source_instance: Text
    exported_at: AwareDatetime
    finding_type: FindingType
    asset_type: Literal["cloud_resource", "package", "container", "agent", "mcp_server", "data_store", "identity"]
    timestamp_format: Literal["iso8601", "unix_ms"] = "iso8601"
    columns: dict[Text, Text] = Field(default_factory=dict, max_length=20)
    severity_values: dict[Text, Literal["critical", "high", "medium", "low", "info", "unknown"]] = Field(
        default_factory=dict, max_length=32
    )


class ImportedControl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: Text
    control: Text
    version: Text | None = None


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _cell(row: dict, path: str) -> Any:
    if not path.startswith("/"):
        return row.get(path)
    value: Any = row
    for part in path[1:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and key.isdecimal() and len(key) < 8 and int(key) < len(value):
            value = value[int(key)]
        else:
            return None
    return value


@overload
def _text(value: Any, *, optional: Literal[False] = False) -> str: ...


@overload
def _text(value: Any, *, optional: Literal[True]) -> str | None: ...


def _text(value: Any, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid lake text cell")
    return value


def _observed(value: Any, timestamp_format: str) -> datetime:
    if timestamp_format == "unix_ms":
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 253402300799999:
            raise ValueError("Invalid millisecond timestamp")
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return _TIMESTAMP.validate_python(_text(value)).astimezone(timezone.utc)


def _finding(row: dict, config: LakeMapping, receipt: dict, source_id: str, ordinal: int) -> dict:
    cells = {name: _cell(row, config.columns.get(name, name)) for name in _FIELDS}
    native_id = _text(cells["finding_id"])
    asset_id = _text(cells["asset_id"])
    provider = (_text(cells["provider"], optional=True) or "").casefold() or None
    account = _text(cells["account_id"], optional=True)
    region = _text(cells["region"], optional=True)
    if config.asset_type in {"cloud_resource", "data_store", "identity"} and not all((provider, account, region)):
        raise ValueError("Cloud lake findings require provider, account and region")
    observed = _observed(cells["observed_at"], config.timestamp_format)
    if observed > config.exported_at:
        raise ValueError("Observation cannot follow snapshot export")
    severity = cells["severity"]
    if isinstance(severity, bool) or not isinstance(severity, (str, int)):
        raise ValueError("Severity requires a label or an explicitly mapped integer")
    if isinstance(severity, int) and str(severity) not in config.severity_values:
        raise ValueError("Numeric severity requires an explicit mapping")
    controls = [] if cells["controls"] is None else cells["controls"]
    if not isinstance(controls, list) or len(controls) > 100:
        raise ValueError("Invalid control mappings")
    tags = [ControlTag(**ImportedControl.model_validate(c).model_dump(), source="lake:source_declared") for c in controls]
    asset = Asset(
        name=_text(cells["asset_name"], optional=True) or asset_id,
        asset_type=config.asset_type,
        identifier=asset_id,
        provider=provider,
        account_ref=normalize_account_ref(provider, account),
        region=region,
        environment=_text(cells["environment"], optional=True),
    )
    occurrence = finding_asset_occurrence_id(
        asset.stable_id, asset.identifier, provider=provider, account_ref=asset.account_ref, region=region
    )
    finding = Finding(
        finding_type=config.finding_type,
        source=FindingSource.EXTERNAL,
        asset=asset,
        severity=config.severity_values.get(str(severity), str(severity)),
        title=_text(cells["title"]),
        description=_text(cells["description"], optional=True) or "",
        controls=tags,
        first_seen=observed.isoformat(),
        cve_id=_text(cells["cve_id"], optional=True),
        fixed_version=_text(cells["fixed_version"], optional=True),
        remediation_guidance=_text(cells["remediation_guidance"], optional=True),
        id=canonical_finding_id(source_id, str(native_id), occurrence, config.finding_type.value),
        evidence={
            "lake_receipt": {**receipt, "row_ordinal": ordinal, "record_id": native_id, "observed_at": observed.isoformat()},
            "observed_at": observed.isoformat(),
            "source": source_id,
        },
        sources=[source_id],
        severity_source="lake:source_declared",
    )
    if config.asset_type == "cloud_resource":
        finding.node_id = f"cloud_resource:{asset.stable_id}"
    result = finding.to_dict()
    result["last_seen"] = observed.isoformat()
    return result


def build_lake_report(rows: list[dict], mapping: dict, *, artifact_sha256: str, object_receipt: dict | None = None) -> dict:
    """Validate the complete bounded snapshot before emitting any finding or report."""
    config = LakeMapping.model_validate(mapping)
    if set(config.columns) - _FIELDS:
        raise ValueError("Unknown mapped field")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 1000 or not all(isinstance(row, dict) for row in rows):
        raise ValueError("Lake snapshot requires 1 to 1000 finding records")
    if len(artifact_sha256) != 64 or any(c not in "0123456789abcdef" for c in artifact_sha256):
        raise ValueError("Invalid artifact digest")
    source_id = "lake:" + _digest([config.provider, config.source_instance])
    receipt = {
        "schema_version": config.schema_version,
        "provider": config.provider,
        "source_instance": config.source_instance,
        "exported_at": config.exported_at.isoformat(),
        "artifact_sha256": artifact_sha256,
        "mapping_sha256": _digest(mapping),
        "integrity": "unsigned_local_digest",
        "collection_coverage": "unknown",
        "execution": "not_established",
        "object": object_receipt or {"kind": "local_export"},
    }
    findings = [_finding(row, config, receipt, source_id, i) for i, row in enumerate(rows, 1)]
    if len({f["id"] for f in findings}) != len(findings):
        raise ValueError("Duplicate finding/resource identity in snapshot")
    return {
        "source_id": source_id,
        "idempotency_key": _digest([source_id, receipt]),
        "agents": [],
        "findings": findings,
        "observed_at": min(f["first_seen"] for f in findings),
        "lake_receipt": receipt,
        "coverage_warnings": [
            {
                "kind": "lake_export_scope_unknown",
                "detail": (
                    "Imported finding records only. Collection completeness, current configuration "
                    "and successful execution are not established."
                ),
            }
        ],
    }
