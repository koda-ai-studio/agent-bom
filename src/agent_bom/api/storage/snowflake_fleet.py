"""Snowflake fleet CRUD operations; connection and schema ownership stay with the store."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.fleet_store import FleetAgent, FleetEndpoint, FleetLifecycleState


class SnowflakeFleetOperations:
    """Fleet operations using the concrete store's connection boundary."""

    def _connect(self) -> Any:
        raise NotImplementedError("A Snowflake store connection is required")

    def put(self, agent: FleetAgent) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                # The MERGE key carries the tenant: matching on agent_id alone
                # made one tenant's registration overwrite another's row.
                """MERGE INTO fleet_agents t USING (SELECT %s AS agent_id, %s AS tenant_id) s
                   ON t.agent_id = s.agent_id AND t.tenant_id = s.tenant_id
                   WHEN MATCHED THEN UPDATE SET
                     canonical_id = %s, name = %s, lifecycle_state = %s, trust_score = %s,
                     updated_at = %s, data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (agent_id, canonical_id, name, lifecycle_state, trust_score, updated_at, tenant_id, data)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    agent.agent_id,
                    agent.tenant_id,
                    agent.canonical_id,
                    agent.name,
                    agent.lifecycle_state.value,
                    agent.trust_score,
                    agent.updated_at,
                    agent.model_dump_json(),
                    agent.agent_id,
                    agent.canonical_id,
                    agent.name,
                    agent.lifecycle_state.value,
                    agent.trust_score,
                    agent.updated_at,
                    agent.tenant_id,
                    agent.model_dump_json(),
                ),
            )

    def get(self, agent_id: str, *, tenant_id: str) -> FleetAgent | None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s", (agent_id, tenant_id))
            row = cur.fetchone()
            if row is None:
                return None
            return FleetAgent.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def get_by_canonical_id(self, canonical_id: str, tenant_id: str | None = None) -> FleetAgent | None:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM fleet_agents WHERE canonical_id = %s", (canonical_id,))
            else:
                cur.execute(
                    "SELECT data FROM fleet_agents WHERE canonical_id = %s AND tenant_id = %s",
                    (canonical_id, tenant_id),
                )
            row = cur.fetchone()
            if row is None:
                return None
            return FleetAgent.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def get_by_name(self, name: str, tenant_id: str | None = None) -> FleetAgent | None:
        with self._connect() as conn:
            cur = conn.cursor()
            # Tenant scope at the app layer — the row access policy allows all
            # rows while agent_bom_tenant_access is empty (its post-init state),
            # so an explicit tenant_id filter is what actually isolates callers.
            if tenant_id is None:
                cur.execute("SELECT data FROM fleet_agents WHERE name = %s", (name,))
            else:
                cur.execute("SELECT data FROM fleet_agents WHERE name = %s AND tenant_id = %s", (name, tenant_id))
            row = cur.fetchone()
            if row is None:
                return None
            return FleetAgent.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def delete(self, agent_id: str, *, tenant_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s", (agent_id, tenant_id))
            return (cur.rowcount or 0) > 0

    def list_all(self, tenant_id: str | None = None) -> list[FleetAgent]:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM fleet_agents ORDER BY name")
            else:
                cur.execute("SELECT data FROM fleet_agents WHERE tenant_id = %s ORDER BY name", (tenant_id,))
            return [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]

    def list_summary(self, tenant_id: str | None = None) -> list[dict]:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT agent_id, canonical_id, name, lifecycle_state, trust_score, updated_at FROM fleet_agents ORDER BY name")
            else:
                cur.execute(
                    "SELECT agent_id, canonical_id, name, lifecycle_state, trust_score, updated_at "
                    "FROM fleet_agents WHERE tenant_id = %s ORDER BY name",
                    (tenant_id,),
                )
            return [
                {
                    "agent_id": r[0],
                    "canonical_id": r[1],
                    "name": r[2],
                    "lifecycle_state": r[3],
                    "trust_score": r[4],
                    "updated_at": str(r[5]) if r[5] else None,
                }
                for r in cur.fetchall()
            ]

    def list_by_tenant(self, tenant_id: str) -> list[FleetAgent]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM fleet_agents WHERE tenant_id = %s ORDER BY name", (tenant_id,))
            return [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]

    def list_tenants(self) -> list[dict]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """SELECT tenant_id, COUNT(*)
                   FROM fleet_agents
                   GROUP BY tenant_id
                   ORDER BY tenant_id"""
            )
            return [{"tenant_id": r[0], "agent_count": r[1]} for r in cur.fetchall()]

    def update_state(self, agent_id: str, state: FleetLifecycleState, *, tenant_id: str) -> bool:
        # agent_id is unique only WITHIN a tenant. The row access policy allows
        # all rows while agent_bom_tenant_access is empty (its post-init state),
        # so this explicit tenant filter is what actually isolates the write.
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s", (agent_id, tenant_id))
            row = cur.fetchone()
        if row is None:
            return False
        agent = FleetAgent.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))
        agent.lifecycle_state = state
        agent.updated_at = datetime.now(timezone.utc).isoformat()
        self.put(agent)
        return True

    def batch_put(self, agents: list[FleetAgent], batch_size: int = 100) -> int:
        """Upsert multiple agents in batched MERGE statements.

        Uses multi-row source via UNION ALL for fewer round-trips to Snowflake.
        """
        if not agents:
            return 0

        total = 0
        for i in range(0, len(agents), batch_size):
            batch = agents[i : i + batch_size]
            # Build parameterised multi-row source
            source_parts: list[str] = []
            params: list = []
            for agent in batch:
                source_parts.append(
                    "SELECT %s AS agent_id, %s AS canonical_id, %s AS name, %s AS lifecycle_state, "
                    "%s AS trust_score, %s AS updated_at, %s AS tenant_id, PARSE_JSON(%s) AS data"
                )
                params.extend(
                    [
                        agent.agent_id,
                        agent.canonical_id,
                        agent.name,
                        agent.lifecycle_state.value,
                        agent.trust_score,
                        agent.updated_at,
                        agent.tenant_id,
                        agent.model_dump_json(),
                    ]
                )

            source_sql = " UNION ALL ".join(source_parts)
            merge_sql = (
                f"MERGE INTO fleet_agents t USING ({source_sql}) s "  # nosec B608
                "ON t.agent_id = s.agent_id AND t.tenant_id = s.tenant_id "
                "WHEN MATCHED THEN UPDATE SET "
                "  canonical_id = s.canonical_id, name = s.name, lifecycle_state = s.lifecycle_state, "
                "  trust_score = s.trust_score, updated_at = s.updated_at, data = s.data "
                "WHEN NOT MATCHED THEN INSERT "
                "  (agent_id, canonical_id, name, lifecycle_state, trust_score, updated_at, tenant_id, data) "
                "  VALUES (s.agent_id, s.canonical_id, s.name, s.lifecycle_state, s.trust_score, "
                "          s.updated_at, s.tenant_id, s.data)"
            )

            with self._connect() as conn:
                conn.cursor().execute(merge_sql, params)
            total += len(batch)

        return total

    def put_endpoint(self, endpoint: FleetEndpoint) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO fleet_endpoints t USING (SELECT %s AS tenant_id, %s AS endpoint_id) s
                   ON t.tenant_id = s.tenant_id AND t.endpoint_id = s.endpoint_id
                   WHEN MATCHED THEN UPDATE SET completeness = %s, updated_at = %s, data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT (tenant_id, endpoint_id, completeness, updated_at, data)
                   VALUES (%s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    endpoint.tenant_id,
                    endpoint.endpoint_id,
                    endpoint.completeness,
                    endpoint.updated_at,
                    endpoint.model_dump_json(),
                    endpoint.tenant_id,
                    endpoint.endpoint_id,
                    endpoint.completeness,
                    endpoint.updated_at,
                    endpoint.model_dump_json(),
                ),
            )

    def get_endpoint(self, endpoint_id: str, *, tenant_id: str) -> FleetEndpoint | None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT data FROM fleet_endpoints WHERE tenant_id = %s AND endpoint_id = %s",
                (tenant_id, endpoint_id),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return FleetEndpoint.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def delete_endpoint(self, endpoint_id: str, *, tenant_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM fleet_endpoints WHERE tenant_id = %s AND endpoint_id = %s",
                (tenant_id, endpoint_id),
            )
            return (cur.rowcount or 0) > 0

    def query_endpoints(
        self,
        tenant_id: str,
        *,
        search: str | None = None,
        completeness: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FleetEndpoint], int]:
        clauses = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if completeness:
            clauses.append("completeness = %s")
            params.append(completeness)
        if search:
            clauses.append("(lower(endpoint_id) LIKE %s OR lower(TO_VARCHAR(data)) LIKE %s)")
            needle = f"%{search.casefold()}%"
            params.extend((needle, needle))
        where = " AND ".join(clauses)
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM fleet_endpoints WHERE {where}", params)  # nosec B608
            total_row = cur.fetchone()
            cur.execute(
                f"SELECT data FROM fleet_endpoints WHERE {where} "  # nosec B608
                "ORDER BY updated_at DESC, endpoint_id LIMIT %s OFFSET %s",
                [*params, int(limit), int(offset)],
            )
            rows = cur.fetchall()
        endpoints = [FleetEndpoint.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0])) for row in rows]
        return endpoints, int(total_row[0] if total_row else 0)
