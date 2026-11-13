"""Persistence contract every fleet agent store implements."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from agent_bom.api.fleet_models import FleetAgent, FleetEndpoint, FleetLifecycleState


class FleetStore(Protocol):
    """Protocol for fleet agent persistence."""

    def put(self, agent: FleetAgent) -> None:
        """Create or replace a fleet agent."""

    def get(self, agent_id: str, *, tenant_id: str) -> FleetAgent | None:
        """Return one agent by id, if any."""

    def get_by_canonical_id(self, canonical_id: str, tenant_id: str | None = None) -> FleetAgent | None:
        """Return one agent by canonical id, if any."""

    def get_by_name(self, name: str) -> FleetAgent | None:
        """Return one agent by name, if any."""

    def delete(self, agent_id: str, *, tenant_id: str) -> bool:
        """Delete one agent; return whether it existed."""

    def list_all(self) -> list[FleetAgent]:
        """Return every agent."""

    def list_summary(self) -> list[dict[str, Any]]:
        """Return lightweight summary rows for every agent."""

    def list_by_tenant(self, tenant_id: str) -> list[FleetAgent]:
        """Return every agent for a tenant."""

    def find_by_identifier(self, tenant_id: str, identifier: str) -> FleetAgent | None:
        """Return the tenant's agent matching an id, canonical id or name, if any."""

    def query_by_tenant(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        environment: str | None = None,
        min_trust: float | None = None,
        search: str | None = None,
        include_quarantined: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FleetAgent], int]:
        """Return one filtered page of a tenant's agents and the total match count."""

    def list_tenants(self) -> list[dict[str, Any]]:
        """Return per-tenant agent counts."""

    # ``agent_id`` is unique only WITHIN a tenant, so the tenant is a required
    # keyword: an unscoped state change is a cross-tenant write.
    def update_state(self, agent_id: str, state: FleetLifecycleState, *, tenant_id: str) -> bool:
        """Set an agent's lifecycle state; return whether it existed."""

    def batch_put(self, agents: list[FleetAgent]) -> int:
        """Create or replace many agents; return the count written."""

    def put_endpoint(self, endpoint: FleetEndpoint) -> None:
        """Create or replace a fleet endpoint."""

    def get_endpoint(self, endpoint_id: str, *, tenant_id: str) -> FleetEndpoint | None:
        """Return one endpoint by id, if any."""

    def delete_endpoint(self, endpoint_id: str, *, tenant_id: str) -> bool:
        """Delete one endpoint; return whether it existed."""

    def query_endpoints(
        self,
        tenant_id: str,
        *,
        search: str | None = None,
        completeness: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FleetEndpoint], int]:
        """Return one filtered page of a tenant's endpoints and the total match count."""
