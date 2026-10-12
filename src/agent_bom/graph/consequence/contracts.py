"""Versioned consequence contracts; no HTTP or persistence dependencies."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=1024, pattern=r"^[^\x00]+$")]
Status = Literal["supported", "conditional", "blocked", "unknown"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ConsequenceRequest(Contract):
    root_node_id: Identifier
    mode: Literal["vulnerability", "assumed_compromise"]
    assume_control: bool = False
    affected_node_id: Identifier | None = None
    max_depth: int = Field(default=6, ge=1, le=10)
    max_states: int = Field(default=256, ge=1, le=1024)
    max_results: int = Field(default=128, ge=1, le=512)
    max_evidence_age_seconds: int = Field(default=3600, ge=1, le=86400)

    @field_validator("root_node_id", "affected_node_id")
    @classmethod
    def nonblank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("identity must not be blank")
        return value

    @model_validator(mode="after")
    def explicit_start(self) -> Self:
        if self.mode == "assumed_compromise" and (not self.assume_control or self.affected_node_id is not None):
            raise ValueError("assumed compromise requires explicit control of the selected agent or principal")
        if self.mode == "vulnerability" and (self.assume_control or self.affected_node_id is None):
            raise ValueError("vulnerability mode requires an affected occurrence, without assuming its control")
        return self


class ActionScope(Contract):
    action: Identifier
    resource: Annotated[str, Field(min_length=1, max_length=2048)]


class SessionBinding(Contract):
    """Collector contract. Config declarations and registered identities are insufficient.

    No current config/provider collector emits this contract. Imported evidence
    needs separate producer qualification; fixture support is not live coverage.
    """

    schema_version: Literal["graph.session-binding.v1"]
    tenant_id: Identifier
    scan_id: Identifier
    source_node_id: Identifier
    identity_node_id: Identifier
    principal_id: Identifier
    provider: Literal["gcp", "azure"]
    session_id: Identifier
    state: Literal["active", "revoked", "expired", "pending"]
    observed_at: str
    expires_at: str
    evidence_ref: Identifier
    scope: list[ActionScope] = Field(min_length=1, max_length=128)


class PrerequisiteCheck(Contract):
    name: str
    status: Literal["recorded", "missing"]
    basis: Literal["inventory", "advisory", "local"]
    value: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class Prerequisites(Contract):
    checks: list[PrerequisiteCheck] = Field(default_factory=list)
    status: Literal["supported", "blocked", "unknown", "not_evaluated"]
    reason_codes: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class Frontier(Contract):
    node_ids: list[str]
    edge_ids: list[str]
    status: Literal["blocked", "unknown"] = "unknown"
    reason_codes: list[str]
    next_collection_step: str


class Consequence(Contract):
    id: str
    status: Status
    category: str
    source_node_id: str
    target_node_id: str
    provider: str | None = None
    principal_id: str | None = None
    action: str | None = None
    resource: str | None = None
    observed_at: str | None = None
    node_ids: list[str]
    edge_ids: list[str]
    session_ids: list[str]
    node_labels: list[str] = Field(default_factory=list)
    node_types: list[str] = Field(default_factory=list)
    evidence_refs: list[str]
    binding_ids: list[str]
    deny_binding_ids: list[str] = Field(default_factory=list)
    reason_codes: list[str]
    observation: str = "not_recorded"
    runtime_references: list[dict[str, str]] = Field(default_factory=list)
    resource_context: dict[str, str] = Field(default_factory=dict)


class Counts(Contract):
    supported: int = 0
    conditional: int = 0
    blocked: int = 0
    unknown: int = 0
    lower_bound: bool = False


class ConsequenceAssessment(Contract):
    schema_version: Literal["graph.consequence.v1"] = "graph.consequence.v1"
    evaluator_version: Literal["1"] = "1"
    capability: Literal["experimental"] = "experimental"
    tenant_id: str
    scan_id: str
    assessed_at: str
    request: ConsequenceRequest
    affected_node_id: str | None
    prerequisites: Prerequisites
    collection_coverage: Literal["unknown"] = "unknown"
    current_access: Literal["not_evaluated"] = "not_evaluated"
    observed_effects: Literal["not_established"] = "not_established"
    collector_independence: Literal["not_assessed"] = "not_assessed"
    counts: Counts
    states_examined: int
    truncated: bool
    reason_codes: list[str]
    consequences: list[Consequence]
    frontier: list[Frontier]
