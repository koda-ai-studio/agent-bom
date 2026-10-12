"""Explicit action mappings and canonical deduplicated consequence counts."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from agent_bom.graph.compromise import CompromiseAction
from agent_bom.graph.consequence.contracts import Consequence, Counts, Status

# Exact provider permission names only. Control-plane metadata reads are not
# data reads. Tool display names never establish repository/merge permissions.
_ACTIONS = {
    ("gcp", "storage.objects.get"): "read_data",
    ("gcp", "storage.objects.create"): "write_data",
    ("gcp", "storage.objects.delete"): "delete_resource",
    ("gcp", "compute.instances.delete"): "delete_resource",
    ("gcp", "compute.instances.update"): "alter_deployment",
    ("azure", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"): "read_data",
    ("azure", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"): "write_data",
    ("azure", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"): "delete_resource",
    ("azure", "Microsoft.Compute/virtualMachines/write"): "alter_deployment",
    ("azure", "Microsoft.Compute/virtualMachines/delete"): "delete_resource",
}


def project_action(
    action: CompromiseAction,
    *,
    node_ids: list[str],
    edge_ids: list[str],
    session_ids: list[str],
    evidence_refs: list[str],
    status: Status,
    reasons: list[str],
) -> Consequence:
    identity = [
        node_ids,
        edge_ids,
        session_ids,
        action.provider,
        action.principal_id,
        action.action,
        action.resource,
        action.observed_at,
        evidence_refs,
    ]
    digest = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:24]
    return Consequence(
        id=f"consequence:{digest}",
        status=status,
        category=_ACTIONS.get((action.provider or "", action.action or ""), "unclassified"),
        source_node_id=action.source_node_id,
        target_node_id=action.target_node_id,
        provider=action.provider,
        principal_id=action.principal_id,
        action=action.action,
        resource=action.resource,
        observed_at=action.observed_at,
        node_ids=node_ids,
        edge_ids=edge_ids,
        session_ids=session_ids,
        evidence_refs=evidence_refs,
        binding_ids=action.binding_ids,
        reason_codes=list(dict.fromkeys(reasons)),
        observation=action.observation,
        runtime_references=action.runtime_references,
    )


def count_consequences(items: list[Consequence], *, truncated: bool) -> Counts:
    groups: dict[tuple[str | None, ...], set[str]] = defaultdict(set)
    for item in items:
        groups[(item.provider, item.action, item.target_node_id, item.resource)].add(item.status)
    counts = dict.fromkeys(("supported", "conditional", "blocked", "unknown"), 0)
    for statuses in groups.values():
        # An alternate supported path survives a blocked path. Unknown paths
        # prevent an all-paths blocked count. Path details retain every status.
        selected = next(status for status in ("supported", "conditional", "unknown", "blocked") if status in statuses)
        counts[selected] += 1
    return Counts(**counts, lower_bound=truncated)


def reconcile_denials(items: list[Consequence]) -> list[Consequence]:
    """A deny for the same recorded request wins across parallel relationships."""

    def key(item: Consequence) -> tuple[str | None, ...]:
        return (item.source_node_id, item.provider, item.principal_id, item.action, item.resource, item.observed_at)

    denials = {key(item) for item in items if item.status == "blocked" and "recorded_denial" in item.reason_codes}
    return [
        item.model_copy(update={"status": "blocked", "reason_codes": [*item.reason_codes, "parallel_recorded_denial"]})
        if item.status in {"supported", "conditional"} and key(item) in denials
        else item
        for item in items
    ]
