"""Dataset, evaluation and blueprint transport using the parent client credentials."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import quote

from agent_bom.connectors.client_values import _quote_path, _strip_none, _strip_query_none
from agent_bom.core.json_types import JsonObject, JsonValue, QueryValue


class GovernanceClientMixin:
    """Share the caller transport and tenant scope for governance operations."""

    tenant_id: str | None

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
        json: Mapping[str, JsonValue] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        raise NotImplementedError

    def register_dataset_version(
        self,
        dataset_id: str,
        *,
        version_id: str | None = None,
        artifact_uri: str | None = None,
        digest: str | None = None,
        digest_algorithm: str | None = None,
        source: str | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """Register a dataset version artifact."""

        return self._request(
            "POST",
            f"/v1/datasets/{_quote_path(dataset_id)}/versions",
            json=_strip_none(
                {
                    "version_id": version_id,
                    "artifact_uri": artifact_uri,
                    "digest": digest,
                    "digest_algorithm": digest_algorithm,
                    "source": source,
                    "metadata": dict(metadata) if metadata is not None else None,
                    "tenant_id": tenant_id or self.tenant_id,
                }
            ),
        )

    def dataset_versions(self, dataset_id: str) -> JsonObject:
        """List versions for a dataset."""

        return self._request("GET", f"/v1/datasets/{_quote_path(dataset_id)}/versions")

    def dataset_version(self, dataset_id: str, version_id: str) -> JsonObject:
        """Return one dataset version record."""

        return self._request("GET", f"/v1/datasets/{_quote_path(dataset_id)}/versions/{_quote_path(version_id)}")

    def register_evaluation_run(
        self,
        *,
        evaluation_id: str | None = None,
        name: str | None = None,
        status: str | None = None,
        dataset_id: str | None = None,
        dataset_version_id: str | None = None,
        trace_id: str | None = None,
        model: str | None = None,
        prompt_hash: str | None = None,
        source: str | None = None,
        scores: Mapping[str, float] | None = None,
        summary: Mapping[str, JsonValue] | None = None,
        cases: Sequence[Mapping[str, JsonValue]] | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """Register an evaluation run linked to datasets, traces, models, and prompt hashes."""

        return self._request(
            "POST",
            "/v1/evaluations",
            json=_strip_none(
                {
                    "evaluation_id": evaluation_id,
                    "name": name,
                    "status": status,
                    "dataset_id": dataset_id,
                    "dataset_version_id": dataset_version_id,
                    "trace_id": trace_id,
                    "model": model,
                    "prompt_hash": prompt_hash,
                    "source": source,
                    "scores": dict(scores) if scores is not None else None,
                    "summary": dict(summary) if summary is not None else None,
                    "cases": [dict(case) for case in cases] if cases is not None else None,
                    "metadata": dict(metadata) if metadata is not None else None,
                    "tenant_id": tenant_id or self.tenant_id,
                }
            ),
        )

    def evaluation_runs(
        self,
        *,
        dataset_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JsonObject:
        """List evaluation runs for the request tenant."""

        return self._request(
            "GET",
            "/v1/evaluations",
            params=_strip_query_none({"dataset_id": dataset_id, "limit": limit, "offset": offset}),
        )

    def evaluation_run(self, evaluation_id: str) -> JsonObject:
        """Return one evaluation run record."""

        return self._request("GET", f"/v1/evaluations/{_quote_path(evaluation_id)}")

    def list_blueprints(self, *, limit: int | None = None, offset: int | None = None) -> JsonObject:
        """List persisted AI-system blueprints for the active tenant (paginated)."""

        params = _strip_query_none({"limit": limit, "offset": offset})
        return self._request("GET", "/v1/governance/blueprints", params=params)

    def get_blueprint(self, blueprint_id: str) -> JsonObject:
        """Fetch one blueprint plus its version history and approval state."""

        return self._request("GET", f"/v1/governance/blueprints/{_quote_path(blueprint_id)}")

    def create_blueprint(
        self,
        *,
        name: str,
        owner: str,
        owner_type: str | None = None,
        description: str | None = None,
        composition: Mapping[str, JsonValue] | None = None,
    ) -> JsonObject:
        """Create a blueprint with an initial draft version 1."""

        body = _strip_none(
            {
                "name": name,
                "owner": owner,
                "owner_type": owner_type,
                "description": description,
                "composition": dict(composition) if composition is not None else None,
            }
        )
        return self._request("POST", "/v1/governance/blueprints", json=body)

    def seed_blueprints(self) -> JsonObject:
        """Seed the tenant's blueprints from the canonical role archetypes (idempotent)."""

        return self._request("POST", "/v1/governance/blueprints/seed")

    def submit_blueprint_version(self, blueprint_id: str, version: int) -> JsonObject:
        """Submit a draft blueprint version for approval (draft → pending)."""

        return self._request("POST", f"/v1/governance/blueprints/{_quote_path(blueprint_id)}/versions/{int(version)}/submit")

    def approve_blueprint_version(self, blueprint_id: str, version: int, *, note: str | None = None) -> JsonObject:
        """Approve a pending blueprint version (requires the admin/governance role)."""

        return self._request(
            "POST",
            f"/v1/governance/blueprints/{_quote_path(blueprint_id)}/versions/{int(version)}/approve",
            json=_strip_none({"note": note}),
        )

    def reject_blueprint_version(self, blueprint_id: str, version: int, *, note: str | None = None) -> JsonObject:
        """Reject a pending blueprint version (requires the admin/governance role)."""

        return self._request(
            "POST",
            f"/v1/governance/blueprints/{_quote_path(blueprint_id)}/versions/{int(version)}/reject",
            json=_strip_none({"note": note}),
        )

    def get_scan_agent_bom(self, job_id: str, agent_id: str) -> JsonObject:
        """Export one recorded agent's composition; display names are not selectors."""
        return self._request("GET", f"/v1/scan/{quote(job_id, safe='')}/agent-bom", params={"agent_id": agent_id})

    def capture_agent_snapshot(self, job_id: str, agent_id: str) -> JsonObject:
        """Persist a completed scan BOM under its immutable snapshot digest."""
        return self._request("POST", "/v1/agent-lifecycle/snapshots", json={"scan_id": job_id, "agent_id": agent_id})

    def agent_lifecycle_history(self, agent_id: str, *, kind: str = "snapshot", limit: int = 50, offset: int = 0) -> JsonObject:
        return self._request(
            "GET", "/v1/agent-lifecycle/history", params={"agent_id": agent_id, "kind": kind, "limit": limit, "offset": offset}
        )

    def get_agent_snapshot(self, snapshot_id: str) -> JsonObject:
        return self._request("GET", "/v1/agent-lifecycle/snapshots/export", params={"snapshot_id": snapshot_id})

    def compare_agent_snapshots(self, before: str, after: str) -> JsonObject:
        return self._request("GET", "/v1/agent-lifecycle/snapshots/compare", params={"before": before, "after": after})

    def register_agent_deployment(self, deployment: JsonObject) -> JsonObject:
        return self._request("POST", "/v1/agent-lifecycle/deployments", json=deployment)

    def register_agent_instance(self, instance: JsonObject) -> JsonObject:
        return self._request("POST", "/v1/agent-lifecycle/instances", json=instance)

    def register_agent_run(self, run: JsonObject) -> JsonObject:
        return self._request("POST", "/v1/agent-lifecycle/runs", json=run)

    def retire_agent_lifecycle_record(self, kind: str, record_id: str) -> JsonObject:
        return self._request("POST", "/v1/agent-lifecycle/retire", params={"kind": kind, "record_id": record_id})
