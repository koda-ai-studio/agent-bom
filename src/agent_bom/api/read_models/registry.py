"""Response contract for the MCP server catalog (``GET /v1/registry``)."""

from __future__ import annotations

from typing import Any

from agent_bom.api.read_models._base import ReadModel, ReadResponse


class RegistryPackage(ReadModel):
    ecosystem: str
    name: str


class RegistryServerRow(ReadModel):
    id: str
    name: str
    publisher: str
    description: str
    category: str | None
    transport: str
    verified: bool
    risk_level: str
    risk_justification: str | None
    license: str | None
    latest_version: str | None
    source_url: str | None
    sigstore_bundle: Any
    command_patterns: list[str]
    credential_env_vars: list[str]
    known_cves: list[str]
    packages: list[RegistryPackage]
    tools: list[str]


class RegistryMeta(ReadModel):
    schema_version: str
    source_url: str
    sources: list[str]
    total_servers: int
    updated: str


class RegistryResponse(ReadResponse):
    # Whole-catalog size; ``total`` is the rows matching the search and filters.
    count: int
    meta: RegistryMeta
    servers: list[RegistryServerRow]
    total: int
    limit: int | None
    offset: int
    has_more: bool
    next_cursor: str | None
    # Per-filter counts; each facet ignores its own selection.
    facets: dict[str, dict[str, int]]
    risk_counts: dict[str, int]
