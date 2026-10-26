"""In-memory and SQLite persistence for managed identities."""

from __future__ import annotations

import builtins
import json
import sqlite3
import threading
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime

from agent_bom.api.identity_grants import AgentJITGrant, require_grant_tenant
from agent_bom.api.identity_models import AgentIdentity
from agent_bom.api.identity_policies import ConditionalAccessPolicy, require_policy_tenant
from agent_bom.api.sqlite_rekey import rekey_table
from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}  # nosec B608 - table is static


_CREATE_IDENTITIES_SQL = """
    CREATE TABLE IF NOT EXISTS {table} (
        identity_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        agent_id TEXT NOT NULL DEFAULT '',
        data TEXT NOT NULL,
        PRIMARY KEY (tenant_id, identity_id)
    )
"""
_IDENTITY_COLUMNS = "identity_id, tenant_id, token_hash, status, issued_at, agent_id, data"


class InMemoryAgentIdentityStore:
    def __init__(self) -> None:
        self._by_id: dict[tuple[str, str], AgentIdentity] = {}
        self._by_hash: dict[str, tuple[str, str]] = {}
        self._jit_by_id: dict[str, AgentJITGrant] = {}
        self._cond_by_id: dict[str, ConditionalAccessPolicy] = {}
        self._lock = threading.Lock()

    def put(self, identity: AgentIdentity) -> None:
        """Upsert keyed by ``(tenant_id, identity_id)``; a token hash stays unique across tenants."""
        key = (identity.tenant_id, identity.identity_id)
        with self._lock:
            holder = self._by_hash.get(identity.token_hash)
            if holder is not None and holder != key:
                raise ValueError("Token hash already belongs to another identity")
            previous = self._by_id.get(key)
            if previous is not None and previous.token_hash != identity.token_hash:
                self._by_hash.pop(previous.token_hash, None)
            self._by_id[key] = identity
            self._by_hash[identity.token_hash] = key

    def get(self, identity_id: str, *, tenant_id: str) -> AgentIdentity | None:
        with self._lock:
            return self._by_id.get((tenant_id, identity_id))

    def get_by_token_hash(self, token_hash: str) -> AgentIdentity | None:
        with self._lock:
            key = self._by_hash.get(token_hash)
            return self._by_id.get(key) if key else None

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200) -> list[AgentIdentity]:
        with self._lock:
            rows = [
                i for i in self._by_id.values() if i.tenant_id == tenant_id and (include_inactive or i.status in ("active", "rotating"))
            ]
            return sorted(rows, key=lambda i: i.issued_at, reverse=True)[:limit]

    def count(self, tenant_id: str, *, include_inactive: bool = False) -> int:
        """Count records without list pagination; lifecycle status is not authority."""
        with self._lock:
            return sum(
                identity.tenant_id == tenant_id and (include_inactive or identity.status in ("active", "rotating"))
                for identity in self._by_id.values()
            )

    def list_by_agent(self, tenant_id: str, agent_id: str, *, limit: int = 200) -> builtins.list[AgentIdentity]:
        with self._lock:
            rows = [i for i in self._by_id.values() if i.tenant_id == tenant_id and (i.agent_id or "").strip() == agent_id]
            return sorted(rows, key=lambda i: i.issued_at, reverse=True)[:limit]

    def put_jit_grant(self, grant: AgentJITGrant, *, tenant_id: str) -> None:
        tenant = require_grant_tenant(grant, tenant_id)
        with self._lock:
            previous = self._jit_by_id.get(grant.grant_id)
            if previous is not None and previous.tenant_id != tenant:
                raise ValueError("JIT grant identity belongs to another tenant")
            self._jit_by_id[grant.grant_id] = replace(grant)

    def get_jit_grant(self, grant_id: str, *, tenant_id: str) -> AgentJITGrant | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            grant = self._jit_by_id.get(grant_id)
            return replace(grant) if grant is not None and grant.tenant_id == tenant else None

    def list_jit_grants(
        self,
        tenant_id: str,
        *,
        identity_id: str | None = None,
        include_inactive: bool = False,
        limit: int = 200,
    ) -> builtins.list[AgentJITGrant]:
        with self._lock:
            rows = [g for g in self._jit_by_id.values() if g.tenant_id == tenant_id]
            if identity_id is not None:
                rows = [g for g in rows if g.identity_id == identity_id]
            if not include_inactive:
                rows = [g for g in rows if g.is_live()]
            return [replace(g) for g in sorted(rows, key=lambda g: g.requested_at, reverse=True)[:limit]]

    def active_jit_grant(
        self,
        tenant_id: str,
        identity_id: str,
        tool_name: str,
        *,
        at: datetime | None = None,
    ) -> AgentJITGrant | None:
        with self._lock:
            candidates = [
                g
                for g in self._jit_by_id.values()
                if g.tenant_id == tenant_id and g.identity_id == identity_id and g.tool_name == tool_name and g.is_live(at=at)
            ]
            return replace(sorted(candidates, key=lambda g: g.expires_at, reverse=True)[0]) if candidates else None

    def iter_all_identities(self, *, limit: int = 10000) -> builtins.list[AgentIdentity]:
        with self._lock:
            return list(self._by_id.values())[:limit]

    def iter_all_jit_grants(self, *, limit: int = 10000) -> builtins.list[AgentJITGrant]:
        with self._lock:
            return [replace(g) for g in list(self._jit_by_id.values())[:limit]]

    def put_conditional_policy(self, policy: ConditionalAccessPolicy, *, tenant_id: str) -> None:
        tenant = require_policy_tenant(policy, tenant_id)
        with self._lock:
            current = self._cond_by_id.get(policy.policy_id)
            if current is not None and current.tenant_id != tenant:
                raise ValueError("Conditional policy identity belongs to another tenant")
            self._cond_by_id[policy.policy_id] = deepcopy(policy)

    def get_conditional_policy(self, policy_id: str, *, tenant_id: str) -> ConditionalAccessPolicy | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            policy = self._cond_by_id.get(policy_id)
            return deepcopy(policy) if policy is not None and policy.tenant_id == tenant else None

    def list_conditional_policies(
        self,
        tenant_id: str,
        *,
        include_disabled: bool = False,
        limit: int = 200,
    ) -> builtins.list[ConditionalAccessPolicy]:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            rows = [p for p in self._cond_by_id.values() if p.tenant_id == tenant_id]
            if not include_disabled:
                rows = [p for p in rows if p.status == "active"]
            return deepcopy(sorted(rows, key=lambda p: (p.priority, p.created_at))[:limit])


class SQLiteAgentIdentityStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        self._conn.execute(_CREATE_IDENTITIES_SQL.format(table="agent_identities"))
        # Revocation is looked up per agent, not per tenant. Without this column
        # the check had to page the tenant's whole roster and could miss an old
        # revoked row behind the page cap.
        if "agent_id" not in _table_columns(self._conn, "agent_identities"):
            self._conn.execute("ALTER TABLE agent_identities ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''")
            self._backfill_agent_ids()
        self._conn.commit()
        # Pre-v3 tables keyed rows by identity_id alone, so a second tenant's write replaced the first's.
        rekey_table(
            self._conn, "agent_identities", key=["tenant_id", "identity_id"], create_sql=_CREATE_IDENTITIES_SQL, columns=_IDENTITY_COLUMNS
        )
        ensure_sqlite_schema_version(self._conn, "agent_identities", version=3)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_tenant ON agent_identities(tenant_id, status)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_hash ON agent_identities(token_hash)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_agent ON agent_identities(tenant_id, agent_id)")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_identity_jit_grants (
                grant_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                identity_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_identity_jit_lookup "
            "ON agent_identity_jit_grants(tenant_id, identity_id, tool_name, status, expires_at)"
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_conditional_access_policies (
                policy_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                status TEXT NOT NULL,
                priority INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_conditional_access_tenant "
            "ON agent_conditional_access_policies(tenant_id, status, priority)"
        )
        self._conn.commit()

    def _backfill_agent_ids(self) -> None:
        rows = self._conn.execute("SELECT tenant_id, identity_id, data FROM agent_identities WHERE agent_id = ''").fetchall()
        for tenant_id, identity_id, data in rows:
            try:
                agent_id = str(json.loads(data).get("agent_id") or "").strip()
            except (json.JSONDecodeError, AttributeError):
                continue
            if agent_id:
                self._conn.execute(
                    "UPDATE agent_identities SET agent_id = ? WHERE tenant_id = ? AND identity_id = ? AND agent_id = ''",
                    (agent_id, tenant_id, identity_id),
                )

    def put(self, identity: AgentIdentity) -> None:
        self._conn.execute(
            "INSERT INTO agent_identities "
            "(identity_id, tenant_id, token_hash, status, issued_at, agent_id, data) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (tenant_id, identity_id) DO UPDATE SET token_hash = excluded.token_hash, status = excluded.status, "
            "issued_at = excluded.issued_at, agent_id = excluded.agent_id, data = excluded.data",
            (
                identity.identity_id,
                identity.tenant_id,
                identity.token_hash,
                identity.status,
                identity.issued_at,
                (identity.agent_id or "").strip(),
                json.dumps(asdict(identity), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get(self, identity_id: str, *, tenant_id: str) -> AgentIdentity | None:
        row = self._conn.execute(
            "SELECT data FROM agent_identities WHERE identity_id = ? AND tenant_id = ?",
            (identity_id, tenant_id),
        ).fetchone()
        return AgentIdentity(**json.loads(row[0])) if row else None

    def get_by_token_hash(self, token_hash: str) -> AgentIdentity | None:
        row = self._conn.execute("SELECT data FROM agent_identities WHERE token_hash = ?", (token_hash,)).fetchone()
        return AgentIdentity(**json.loads(row[0])) if row else None

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200) -> list[AgentIdentity]:
        if include_inactive:
            rows = self._conn.execute(
                "SELECT data FROM agent_identities WHERE tenant_id = ? ORDER BY issued_at DESC LIMIT ?", (tenant_id, limit)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM agent_identities WHERE tenant_id = ? AND status IN ('active', 'rotating') "
                "ORDER BY issued_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [AgentIdentity(**json.loads(r[0])) for r in rows]

    def count(self, tenant_id: str, *, include_inactive: bool = False) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM agent_identities WHERE tenant_id = ? AND (? OR status IN ('active', 'rotating'))",
            (tenant_id, include_inactive),
        ).fetchone()
        return int(row[0])

    def list_by_agent(self, tenant_id: str, agent_id: str, *, limit: int = 200) -> builtins.list[AgentIdentity]:
        rows = self._conn.execute(
            "SELECT data FROM agent_identities WHERE tenant_id = ? AND agent_id = ? ORDER BY issued_at DESC LIMIT ?",
            (tenant_id, agent_id, limit),
        ).fetchall()
        return [AgentIdentity(**json.loads(r[0])) for r in rows]

    def put_jit_grant(self, grant: AgentJITGrant, *, tenant_id: str) -> None:
        tenant = require_grant_tenant(grant, tenant_id)
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO agent_identity_jit_grants "
                "(grant_id, tenant_id, identity_id, tool_name, status, requested_at, expires_at, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (grant_id) DO UPDATE SET "
                "identity_id = excluded.identity_id, tool_name = excluded.tool_name, requested_at = excluded.requested_at, "
                "status = excluded.status, expires_at = excluded.expires_at, data = excluded.data "
                "WHERE agent_identity_jit_grants.tenant_id = excluded.tenant_id",
                (
                    grant.grant_id,
                    tenant,
                    grant.identity_id,
                    grant.tool_name,
                    grant.status,
                    grant.requested_at,
                    grant.expires_at,
                    json.dumps(asdict(grant), sort_keys=True),
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("JIT grant identity belongs to another tenant")

    def get_jit_grant(self, grant_id: str, *, tenant_id: str) -> AgentJITGrant | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute(
            "SELECT data FROM agent_identity_jit_grants WHERE grant_id = ? AND tenant_id = ?", (grant_id, tenant)
        ).fetchone()
        grant = AgentJITGrant(**json.loads(row[0])) if row else None
        if grant is not None:
            require_grant_tenant(grant, tenant)
            if grant.grant_id != grant_id:
                raise ValueError("JIT grant record identity does not match")
        return grant

    def list_jit_grants(
        self,
        tenant_id: str,
        *,
        identity_id: str | None = None,
        include_inactive: bool = False,
        limit: int = 200,
    ) -> builtins.list[AgentJITGrant]:
        if identity_id is not None:
            rows = self._conn.execute(
                "SELECT data FROM agent_identity_jit_grants WHERE tenant_id = ? AND identity_id = ? ORDER BY requested_at DESC LIMIT ?",
                (tenant_id, identity_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM agent_identity_jit_grants WHERE tenant_id = ? ORDER BY requested_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        grants = [AgentJITGrant(**json.loads(r[0])) for r in rows]
        if not include_inactive:
            grants = [g for g in grants if g.is_live()]
        return grants[:limit]

    def active_jit_grant(
        self,
        tenant_id: str,
        identity_id: str,
        tool_name: str,
        *,
        at: datetime | None = None,
    ) -> AgentJITGrant | None:
        rows = self._conn.execute(
            "SELECT data FROM agent_identity_jit_grants "
            "WHERE tenant_id = ? AND identity_id = ? AND tool_name = ? AND status = 'active' "
            "ORDER BY expires_at DESC LIMIT 20",
            (tenant_id, identity_id, tool_name),
        ).fetchall()
        grants = [AgentJITGrant(**json.loads(r[0])) for r in rows]
        live = [g for g in grants if g.is_live(at=at)]
        return live[0] if live else None

    def iter_all_identities(self, *, limit: int = 10000) -> builtins.list[AgentIdentity]:
        rows = self._conn.execute("SELECT data FROM agent_identities ORDER BY issued_at ASC LIMIT ?", (limit,)).fetchall()
        return [AgentIdentity(**json.loads(r[0])) for r in rows]

    def iter_all_jit_grants(self, *, limit: int = 10000) -> builtins.list[AgentJITGrant]:
        rows = self._conn.execute("SELECT data FROM agent_identity_jit_grants ORDER BY requested_at ASC LIMIT ?", (limit,)).fetchall()
        return [AgentJITGrant(**json.loads(r[0])) for r in rows]

    def put_conditional_policy(self, policy: ConditionalAccessPolicy, *, tenant_id: str) -> None:
        tenant = require_policy_tenant(policy, tenant_id)
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO agent_conditional_access_policies "
                "(policy_id, tenant_id, status, priority, created_at, data) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (policy_id) DO UPDATE SET status = excluded.status, priority = excluded.priority, "
                "created_at = excluded.created_at, data = excluded.data "
                "WHERE agent_conditional_access_policies.tenant_id = excluded.tenant_id",
                (
                    policy.policy_id,
                    tenant,
                    policy.status,
                    int(policy.priority),
                    policy.created_at,
                    json.dumps(asdict(policy), sort_keys=True),
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("Conditional policy identity belongs to another tenant")

    def get_conditional_policy(self, policy_id: str, *, tenant_id: str) -> ConditionalAccessPolicy | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute(
            "SELECT data FROM agent_conditional_access_policies WHERE policy_id = ? AND tenant_id = ?", (policy_id, tenant)
        ).fetchone()
        policy = ConditionalAccessPolicy(**json.loads(row[0])) if row else None
        if policy is not None:
            require_policy_tenant(policy, tenant)
            if policy.policy_id != policy_id:
                raise ValueError("Conditional policy record identity does not match")
        return policy

    def list_conditional_policies(
        self,
        tenant_id: str,
        *,
        include_disabled: bool = False,
        limit: int = 200,
    ) -> builtins.list[ConditionalAccessPolicy]:
        tenant_id = require_explicit_tenant_id(tenant_id)
        if include_disabled:
            rows = self._conn.execute(
                "SELECT data FROM agent_conditional_access_policies WHERE tenant_id = ? ORDER BY priority ASC, created_at ASC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM agent_conditional_access_policies WHERE tenant_id = ? AND status = 'active' "
                "ORDER BY priority ASC, created_at ASC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [ConditionalAccessPolicy(**json.loads(r[0])) for r in rows]
