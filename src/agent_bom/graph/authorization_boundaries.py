"""Persist negative evaluator receipts without adding traversable access edges."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import replace
from typing import Any

from agent_bom.cloud.authorization_evaluator import evaluate_authorization
from agent_bom.cloud.authorization_evidence import (
    AuthorizationDecision,
    AuthorizationEvaluation,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationRequest,
)
from agent_bom.graph.container import UnifiedGraph

_MAX_RECORDS = 4096
_MAX_PER_PRINCIPAL = 128
_REASON_CODES = frozenset(
    {
        "unevaluated_allow_condition",
        "unevaluated_deny_condition",
        "unevaluated_boundary_condition",
        "boundary_excluded",
        "invalid_request",
        "resource_outside_bundle_scope",
        "unsupported_boundary_provider",
    }
)


def decision_receipt(
    bundle: AuthorizationEvidenceBundle, principal_id: str, action: str, resource: str, result: AuthorizationEvaluation
) -> dict[str, Any]:
    return {
        "source": "authorization-evidence",
        "provider": bundle.provider.value,
        "principal_id": principal_id,
        "decision": result.decision.value,
        "action": action,
        "resource": resource,
        "binding_ids": sorted(result.matched_allow_bindings),
        "observed_at": bundle.observed_at.isoformat() if bundle.observed_at else None,
    }


class AuthorizationBoundaries:
    """Batch writes to support memory-backed and SQLite-backed graph builders."""

    def __init__(self) -> None:
        self.records: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.limited_principals: set[str] = set()
        self.count = 0

    def record(
        self,
        principal_node_id: str,
        target_node_id: str,
        bundle: AuthorizationEvidenceBundle,
        receipt: dict[str, Any],
        result: AuthorizationEvaluation,
    ) -> None:
        if self.count >= _MAX_RECORDS or len(self.records[principal_node_id]) >= _MAX_PER_PRINCIPAL:
            self.limited_principals.add(principal_node_id)
            return
        reasons = [code for code in result.diagnostics if code in _REASON_CODES]
        if bundle.incomplete_required_sources():
            reasons.append("incomplete_required_sources")
        if result.diagnostics and not reasons:
            reasons.append("authorization_evidence_unresolved")
        record = {
            **receipt,
            "principal_node_id": principal_node_id,
            "target_node_id": target_node_id,
            "deny_binding_ids": sorted(result.matched_deny_bindings),
            "reason_codes": sorted(set(reasons)),
            "source_gaps": list(bundle.incomplete_required_sources()),
        }
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        record["evidence_ref"] = "authorization-boundary:" + hashlib.sha256(encoded).hexdigest()
        self.records[principal_node_id].append(record)
        self.count += 1

    def persist(self, graph: UnifiedGraph) -> list[str]:
        for principal_id in sorted(self.records.keys() | self.limited_principals):
            node = graph.nodes.get(principal_id)
            if node is None:
                continue
            prior = node.attributes.get("authorization_boundaries", [])
            prior = prior if isinstance(prior, list) else []
            merged = {json.dumps(row, sort_keys=True): row for row in [*prior, *self.records.get(principal_id, [])]}
            rows = [merged[key] for key in sorted(merged)]
            limited = (
                principal_id in self.limited_principals
                or len(rows) > _MAX_PER_PRINCIPAL
                or node.attributes.get("authorization_boundaries_truncated") is True
            )
            attributes = {
                **node.attributes,
                "authorization_boundaries": rows[:_MAX_PER_PRINCIPAL],
                "authorization_boundaries_truncated": limited,
            }
            graph.add_node(replace(node, attributes=attributes))
        return ["authorization_boundary_limit"] if self.limited_principals else []


def evaluate_request(
    bundle: AuthorizationEvidenceBundle,
    principal_id: str,
    action: str,
    resource: str,
    principal_node_id: str,
    target_node_id: str,
    boundaries: AuthorizationBoundaries,
) -> AuthorizationEvaluation:
    # Provider normalizers preserve control/data planes; GCP has one unified
    # permission list. Evaluate ANY rather than guessing a plane from its name.
    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=bundle.provider, principal_id=principal_id, action=action, resource=resource, plane=AuthorizationPlane.ANY
        ),
    )
    if result.decision is not AuthorizationDecision.ALLOW:
        boundaries.record(
            principal_node_id, target_node_id, bundle, decision_receipt(bundle, principal_id, action, resource, result), result
        )
    return result
