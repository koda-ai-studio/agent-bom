"""Backend-neutral analytics protocol and disabled-store implementation."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# ------------------------------------------------------------------
# Protocol
# ------------------------------------------------------------------


@runtime_checkable
class AnalyticsStore(Protocol):
    """Protocol for analytics persistence (OLAP).

    Every write carries a ``tenant_id`` so the shared ClickHouse cluster
    stays segregated per-tenant at row level. Read methods accept an
    optional ``tenant_id``; ``None`` is an explicit cross-tenant scan used
    only by admin-scoped operator dashboards. All call sites on the
    user-facing API path must supply the tenant_id from the request state.
    """

    def record_scan(
        self,
        scan_id: str,
        agent_name: str,
        vulns: list[dict],
        *,
        tenant_id: str = "default",
    ) -> None:
        """Append vulnerability scan results."""
        ...

    def record_event(self, event: dict, *, tenant_id: str = "default") -> None:
        """Append a runtime protection event."""
        ...

    def record_events(self, events: list[dict], *, tenant_id: str = "default") -> None:
        """Append multiple runtime protection events in one batch."""
        ...

    def record_posture(self, agent_name: str, snapshot: dict, *, tenant_id: str = "default") -> None:
        """Append a posture score snapshot."""
        ...

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        """Append a fleet-agent snapshot."""
        ...

    def record_compliance_control(self, control: dict, *, tenant_id: str = "default") -> None:
        """Append a compliance control measurement."""
        ...

    def record_cis_benchmark_checks(self, checks: list[dict], *, tenant_id: str = "default") -> None:
        """Append normalized CIS benchmark check rows."""
        ...

    def record_audit_event(self, event: dict) -> None:
        """Append an audit event for analytics/trending."""
        ...

    def query_vuln_trends(
        self,
        days: int = 30,
        agent: str | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Vulnerability counts grouped by day and severity."""
        ...

    def query_top_cves(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        """Most frequent CVEs across all scans."""
        ...

    def query_posture_history(
        self,
        agent: str | None = None,
        days: int = 90,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Posture grade time-series."""
        ...

    def query_event_summary(self, hours: int = 24, *, tenant_id: str | None = None) -> list[dict]:
        """Runtime event counts grouped by type."""
        ...

    def query_top_riskiest_agents(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        """Top fleet agents by trust/risk posture."""
        ...

    def query_compliance_heatmap(self, days: int = 30, *, tenant_id: str | None = None) -> list[dict]:
        """Compliance control pass/fail summary grouped by framework."""
        ...

    def query_cis_benchmark_checks(
        self,
        *,
        cloud: str | None = None,
        status: str | None = None,
        priority: int | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """List normalized CIS benchmark checks."""
        ...

    def record_scan_metadata(self, metadata: dict, *, tenant_id: str = "default") -> None:
        """Record scan-level metadata (agent count, vuln count, grade)."""
        ...

    def close(self) -> None:
        """Flush and release any buffered resources."""
        ...


# ------------------------------------------------------------------
# Null implementation (default — zero overhead)
# ------------------------------------------------------------------


class NullAnalyticsStore:
    """Silent no-op analytics store used when ClickHouse is not configured."""

    def record_scan(
        self,
        scan_id: str,
        agent_name: str,
        vulns: list[dict],
        *,
        tenant_id: str = "default",
    ) -> None:
        pass

    def record_event(self, event: dict, *, tenant_id: str = "default") -> None:
        pass

    def record_events(self, events: list[dict], *, tenant_id: str = "default") -> None:
        pass

    def record_posture(self, agent_name: str, snapshot: dict, *, tenant_id: str = "default") -> None:
        pass

    def record_fleet_snapshot(self, snapshot: dict) -> None:
        pass

    def record_compliance_control(self, control: dict, *, tenant_id: str = "default") -> None:
        pass

    def record_cis_benchmark_checks(self, checks: list[dict], *, tenant_id: str = "default") -> None:
        pass

    def record_audit_event(self, event: dict) -> None:
        pass

    def query_vuln_trends(
        self,
        days: int = 30,
        agent: str | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        return []

    def query_top_cves(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        return []

    def query_posture_history(
        self,
        agent: str | None = None,
        days: int = 90,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        return []

    def query_event_summary(self, hours: int = 24, *, tenant_id: str | None = None) -> list[dict]:
        return []

    def query_top_riskiest_agents(self, limit: int = 20, *, tenant_id: str | None = None) -> list[dict]:
        return []

    def query_compliance_heatmap(self, days: int = 30, *, tenant_id: str | None = None) -> list[dict]:
        return []

    def query_cis_benchmark_checks(
        self,
        *,
        cloud: str | None = None,
        status: str | None = None,
        priority: int | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict]:
        return []

    def record_scan_metadata(self, metadata: dict, *, tenant_id: str = "default") -> None:
        pass

    def close(self) -> None:
        pass
