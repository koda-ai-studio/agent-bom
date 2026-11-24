"""Documented 200 contract for ``/v1/affected``: one answer to "am I affected by this advisory or package?"."""

from __future__ import annotations

from typing import Literal

from agent_bom.api.read_models._base import ReadModel, ReadResponse


class AffectedQuery(ReadModel):
    raw: str
    kind: Literal["advisory", "package"]
    advisory: str | None = None
    package: str | None = None
    version: str | None = None


class AffectedFindings(ReadModel):
    total: int
    open: int
    resolved: int
    suppressed: int
    severity: dict[str, int]
    kev: bool
    fix_available: int
    no_fix: int
    internet_exposed: int
    advisories: list[str]
    packages: list[str]


class AffectedExposure(ReadModel):
    first_seen: str | None
    last_seen: str | None
    still_open: bool
    last_resolved_at: str | None


class AffectedAsset(ReadModel):
    name: str
    asset_type: str | None = None
    package: str | None = None
    version: str | None = None
    advisory: str | None = None
    status: str | None = None
    severity: str | None = None
    provider: str | None = None
    environment: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    fixed_version: str | None = None
    finding_id: str | None = None


class AffectedReachItem(ReadModel):
    id: str
    label: str
    entity_type: str


class AffectedReach(ReadModel):
    by_kind: dict[str, int]
    items: dict[str, list[AffectedReachItem]]
    agents_on_findings: list[str]
    servers_on_findings: list[str]
    basis: Literal["graph_snapshot", "findings_only", "unavailable"]
    scan_id: str | None = None
    advisories_walked: list[str]
    note: str | None = None


class AffectedInventory(ReadModel):
    """The advisory matched against stored inventory ranges: catches assets no scan has turned into a finding yet."""

    available: bool
    affected: int = 0
    possibly_affected: int = 0
    not_affected: int = 0
    assets_examined: int = 0
    complete: bool | None = None
    source: str | None = None
    href: str | None = None
    note: str | None = None


class AffectedResponse(ReadResponse):
    tenant_id: str
    query: AffectedQuery
    verdict: Literal["affected", "possibly_affected", "previously_affected", "not_found"]
    verdict_basis: list[Literal["findings", "inventory_match"]]
    inventory: AffectedInventory
    findings: AffectedFindings
    exposure: AffectedExposure
    assets: list[AffectedAsset]
    assets_truncated: bool
    reach: AffectedReach
    findings_truncated: bool
    findings_href: str


__all__ = ["AffectedResponse"]
