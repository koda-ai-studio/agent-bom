"""Request models and row normalization for bulk finding ingest and package checks."""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Annotated, Any, Literal, NamedTuple

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from agent_bom.api.finding_job_metadata import advisory_data_degraded, scan_collection_incomplete_reasons
from agent_bom.api.finding_lifecycle import ingest_asset_key, ingest_asset_scope
from agent_bom.canonical_ids import canonical_finding_id
from agent_bom.domain.asset_identity import canonical_asset_id, finding_asset_occurrence_id
from agent_bom.evidence.finding_observation import ReconfirmationReason
from agent_bom.evidence.finding_reach_sources import CLIENT_REACH_CLAIM_FIELDS, without_fields

_BULK_FINDINGS_MAX_ITEMS = 1000
_BULK_FINDINGS_SOURCE_MAX_LENGTH = 128


class BulkScanRun(BaseModel):
    """The completeness receipt of the scan behind a reconciling batch."""

    model_config = ConfigDict(extra="ignore")

    outcome: Literal["complete", "partial", "failed"] = "complete"
    issues: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    scopes: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    incomplete_scope_count: int = Field(default=0, ge=0, le=100)


def reconcile_skip_reasons(scan_run: BulkScanRun | None) -> list[str]:
    """Why a batch's absences prove nothing; empty when none were declared."""
    if scan_run is None:
        return []
    job: Any = SimpleNamespace(result={"scan_run": scan_run.model_dump()})
    reasons = scan_collection_incomplete_reasons(job)
    if advisory_data_degraded(job):
        reasons = sorted({*reasons, ReconfirmationReason.ADVISORY_DATA_DEGRADED.value})
    return reasons


class ReconcilePlan(NamedTuple):
    """What one batch's absences may resolve, and what the response reports about it."""

    requested: bool
    skip_reasons: list[str]
    scope_assets: set[str] | None

    @property
    def store_kwargs(self) -> dict[str, Any]:
        return {"reconcile_absent": self.requested and not self.skip_reasons, "scope_assets": self.scope_assets}

    def receipt(self, reconciled: int) -> dict[str, Any]:
        if not self.requested:
            return {}
        return {"reconciled": reconciled, **({"reconcile_skipped": self.skip_reasons} if self.skip_reasons else {})}


def reconcile_plan(body: BulkFindingsRequest, payloads: list[dict[str, Any]]) -> ReconcilePlan:
    assets = None
    if body.reconcile_scope == "assets":
        assets = {str(row.get("ingest_asset") or "") for row in payloads} | {ingest_asset_scope(item) for item in body.scanned_assets}
    return ReconcilePlan(body.reconcile_absent, reconcile_skip_reasons(body.scan_run), assets)


class BulkFindingsRequest(BaseModel):
    """Normalized finding ingest for headless clients and agent runtimes."""

    model_config = ConfigDict(extra="forbid")

    findings: list[dict[str, Any]] = Field(max_length=_BULK_FINDINGS_MAX_ITEMS)
    source: str = Field(default="api", min_length=1, max_length=_BULK_FINDINGS_SOURCE_MAX_LENGTH)
    schema_version: str = Field(default="v1", min_length=1, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str | None = Field(default=None, description="Deprecated compatibility field; request tenant scope is authoritative.")
    observed_at: str | None = Field(
        default=None,
        description="Observation timestamp from scan completion; defaults to ingest time when omitted.",
    )
    reconcile_absent: StrictBool = Field(
        default=False,
        description=(
            "When true, mark open findings absent from this complete scan as resolved at observed_at. "
            "Only findings of the same source on the assets this batch names or lists in scanned_assets are affected."
        ),
    )
    reconcile_scope: Literal["assets", "source"] = Field(
        default="assets",
        description="assets (default) limits reconciliation to scanned assets; source asserts the batch covers all of this source.",
    )
    scanned_assets: list[Annotated[str, Field(min_length=1, max_length=512)]] = Field(
        default_factory=list,
        max_length=_BULK_FINDINGS_MAX_ITEMS,
        description="Asset identifiers (asset.identifier, else asset.name) this scan covered, including assets with no findings.",
    )
    scan_run: BulkScanRun | None = Field(
        default=None,
        description="Scan completeness receipt; a partial, failed or advisory-degraded scan reconciles nothing and says why.",
    )

    @model_validator(mode="after")
    def _empty_batch_needs_a_declared_scan(self) -> BulkFindingsRequest:
        if not self.findings and not (self.reconcile_absent and (self.scanned_assets or self.reconcile_scope == "source")):
            raise ValueError("an empty batch must set reconcile_absent and declare scanned_assets or reconcile_scope=source")
        return self

    @field_validator("findings")
    @classmethod
    def _findings_must_be_objects(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in value:
            if not item:
                raise ValueError("findings must contain non-empty objects")
        return value

    @field_validator("source")
    @classmethod
    def _source_must_be_stable_label(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("source is required")
        return normalized


class PackageCheckRequest(BaseModel):
    """Pinned package check shared with the CLI and MCP surfaces."""

    model_config = ConfigDict(extra="forbid")

    package: str = Field(min_length=1, max_length=512)
    ecosystem: str = Field(default="npm", min_length=1, max_length=32)
    version: str | None = Field(default=None, max_length=256)
    offline: bool = False

    @field_validator("package")
    @classmethod
    def _package_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("package is required")
        return normalized

    @field_validator("ecosystem")
    @classmethod
    def _ecosystem_must_be_supported(cls, value: str) -> str:
        from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
        from agent_bom.mcp_server_runtime import validate_ecosystem

        return validate_ecosystem(value, SUPPORTED_PACKAGE_ECOSYSTEM_SET)


def _derive_bulk_finding_id(row: dict[str, Any], *, source: str) -> str:
    """Return a deterministic identity key for a bulk finding lacking an ``id``.

    Idempotency requires the identity key to be a pure function of finding
    content — never the per-attempt ``batch_id`` or wall clock. We fold in the
    stable discriminators (source, rule/vuln, location, package) via the shared
    ``uuid5`` canonicaliser so a resent identical batch collapses onto the same
    rows instead of appending duplicates.
    """
    raw_asset = row.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    rule = row.get("vulnerability_id") or row.get("cve_id") or row.get("rule_id") or row.get("title") or ""
    location = row.get("location") or row.get("file_path") or asset.get("location") or ""
    package = row.get("package") or row.get("package_name") or asset.get("name") or asset.get("identifier") or ""
    stable_asset = asset.get("stable_id") or asset.get("canonical_id")
    provider = asset.get("provider") or row.get("provider")
    account = asset.get("account_ref") or row.get("account_ref")
    region = asset.get("region") or row.get("region")
    identifier = asset.get("identifier")
    if any(value is not None and not isinstance(value, str) for value in (stable_asset, identifier, provider, account, region)):
        raise HTTPException(status_code=422, detail="finding asset identity and scope fields must be strings")
    if not stable_asset and (identifier or provider or account or region):
        stable_asset = canonical_asset_id(
            str(asset.get("asset_type") or "external"),
            str(identifier or f"{package}:{location}"),
            provider=provider,
            account_ref=account,
            region=region,
        )
    if stable_asset:
        stable_asset = finding_asset_occurrence_id(stable_asset, identifier, provider=provider, account_ref=account, region=region)
        # A discovered asset label may change without replacing the resource.
        package_key = row.get("package") or row.get("package_name") or ""
        return canonical_finding_id(
            source, str(rule), str(location), str(stable_asset), str(package_key), str(row.get("package_version") or "")
        )
    return canonical_finding_id(source, str(rule), str(location), str(package))


def _coerce_bulk_severity(value: Any, *, ordinal: int) -> str:
    """Validate/normalise a bulk finding's severity, failing closed on bad types.

    A non-string severity (nested object, number, list) cannot be honestly
    mapped to a severity bucket — accepting it materialised a row that leaked the
    value verbatim and never matched the severity filter. Reject it with a 422.
    A string severity is normalised to the canonical enum; an unrecognised label
    maps to ``unknown`` explicitly (never leaked as-is).
    """
    if value is None:
        return "unknown"
    if not isinstance(value, str):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: severity must be a string severity label, not {type(value).__name__}",
        )
    from agent_bom.core.severity import normalize_severity

    return normalize_severity(value)


def _coerce_bulk_cvss(value: Any, *, ordinal: int) -> float | None:
    """Validate/coerce a bulk finding's cvss_score to a 0.0-10.0 float or null.

    A non-numeric string (``"NaNstring"``), a nested object, NaN/inf, or an
    out-of-range number cannot be an honest CVSS base score — accepting it left a
    value that never matched a cvss filter. Reject it with a 422. ``None`` /
    absent is allowed (no score); a numeric string that parses cleanly in range
    is coerced to float.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a number in 0.0-10.0 or null, not bool",
        )
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"finding {ordinal}: cvss_score must be a number in 0.0-10.0 or null",
            ) from None
    else:
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a number in 0.0-10.0 or null, not {type(value).__name__}",
        )
    if not math.isfinite(score) or not (0.0 <= score <= 10.0):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a finite number within 0.0-10.0",
        )
    return score


def _normalized_bulk_finding(row: dict[str, Any], *, source: str, batch_id: str, ordinal: int) -> dict[str, Any]:
    # A pushed row cannot corroborate its own reachability; only the server's path join can.
    payload = without_fields(row, CLIENT_REACH_CLAIM_FIELDS)
    client_id = row.get("id")
    # Client-stable ids win; otherwise derive a content-deterministic id so
    # resends collapse (idempotent) rather than mint a fresh batch_id:ordinal.
    payload["id"] = str(client_id) if client_id else _derive_bulk_finding_id(row, source=source)
    payload.setdefault("source", source)
    # The batch's source owns reconciliation, even when a row names its own scanner.
    payload["ingest_source"] = source
    payload["ingest_asset"] = ingest_asset_key(row)
    # Fail closed on garbage severity/cvss types instead of materialising a row
    # that leaks the value verbatim and never matches the severity/cvss filter.
    payload["severity"] = _coerce_bulk_severity(row.get("severity"), ordinal=ordinal)
    cvss = _coerce_bulk_cvss(row.get("cvss_score"), ordinal=ordinal)
    if cvss is None:
        payload.pop("cvss_score", None)
    else:
        payload["cvss_score"] = cvss
    payload["origin"] = "bulk_ingest"
    payload["batch_id"] = batch_id
    payload["bulk_ordinal"] = ordinal
    return payload
