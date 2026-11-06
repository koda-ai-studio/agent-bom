"""Read models for AI advice. Every field here is advisory and separate from scanner severity."""

from __future__ import annotations

from typing import Any

from agent_bom.api.read_models._base import ReadModel, ReadResponse


class AIAssessmentProvenance(ReadModel):
    model: str
    provider: str | None = None
    model_digest: str | None = None
    model_revision: str | None = None
    prompt_version: str | None = None
    dataset_version: str | None = None
    generated_at: str | None = None
    run_id: str | None = None
    prompt_sha256: str | None = None
    response_sha256: str | None = None


class AIAssessmentRow(ReadModel):
    finding_id: str
    verdict: str
    confidence: str
    false_positive_likelihood: str | None = None
    classification: str | None = None
    rationale: str
    advisory: bool
    guard_applied: bool | None = None
    protected_reasons: list[str] | None = None
    scan_id: str | None = None
    advice_covers_occurrences: int | None = None
    group_occurrences: int | None = None
    provenance: AIAssessmentProvenance


class AITriageRun(ReadModel):
    scan_id: str
    created_at: str
    status: str
    reason: str | None = None
    provider: str | None = None
    model: str | None = None
    model_standing: str | None = None
    local: bool | None = None
    prompt_version: str | None = None
    dataset_version: str | None = None
    triage_scope: dict[str, Any] | None = None
    call_budget: dict[str, Any] | None = None


class AIStatusResponse(ReadResponse):
    schema_version: str
    state: str
    reason: str
    advisory_only: bool
    model: str | None = None
    last_run: AITriageRun | None = None


class GraphCitation(ReadModel):
    ref: str
    kind: str
    id: str
    label: str
    traversable: bool | None = None
    source: str | None = None
    target: str | None = None
    relationship: str | None = None
    direction: str | None = None
    evidence_keys: list[str] | None = None


class GraphClaim(ReadModel):
    text: str
    claim_type: str
    note: str | None = None
    citations: list[GraphCitation]


class GraphExplanationProvenance(ReadModel):
    model: str
    provider: str
    model_digest: str | None = None
    prompt_version: str
    generated_at: str


class GraphExplanationResponse(ReadResponse):
    schema_version: str
    advisory: bool
    label: str
    status: str
    claims: list[GraphClaim]
    rejected_claims: dict[str, int]
    evidence_limits: list[str]
    provenance: GraphExplanationProvenance
