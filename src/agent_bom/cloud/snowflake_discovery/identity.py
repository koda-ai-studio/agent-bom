"""Live Snowflake role-grant graph collection and object-graph identity merge."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from agent_bom.security import sanitize_error

from ..snowflake_common import _quote_sf_identifier as _quote_sf_identifier
from ..snowflake_common import _record_snowflake_inventory_failure as _record_snowflake_inventory_failure
from ..snowflake_object_graph import _LIVE_GRANT_OBJECT_TYPES as _LIVE_GRANT_OBJECT_TYPES
from ._base import _for_each_row


class _LiveRoleGraph:
    """Deduping accumulator for live ``SHOW GRANTS TO/OF ROLE`` rows."""

    def __init__(self) -> None:
        self.grants: list[dict[str, Any]] = []
        self.memberships: list[dict[str, Any]] = []
        # Dedupe so the two SHOW directions don't double-emit the same role→role edge.
        self.seen_member: set[tuple[str, str]] = set()
        self.seen_user: set[tuple[str, str]] = set()
        self.seen_grant: set[tuple[str, str, str]] = set()

    def add_role_membership(self, child: str, parent: str) -> None:
        if not child or not parent or child == parent:
            return
        key = (child, parent)
        if key in self.seen_member:
            return
        self.seen_member.add(key)
        self.memberships.append({"role": child, "parent": parent, "member_type": "role"})

    def add_user_membership(self, user_name: str, role: str) -> None:
        if not user_name or not role:
            return
        key = (user_name, role)
        if key in self.seen_user:
            return
        self.seen_user.add(key)
        self.memberships.append({"user": user_name, "role": role, "member_type": "user"})

    def add_grant_to(self, role_name: str, r: dict[str, Any]) -> None:
        """One ``SHOW GRANTS TO ROLE`` row: an object grant or a role→role parent."""
        granted_on = str(r.get("granted_on", "") or "").upper()
        privilege = str(r.get("privilege", "") or "")
        obj_name = str(r.get("name", "") or "")
        if granted_on == "ROLE" and privilege.upper() == "USAGE" and obj_name:
            # This role USAGE-on another role => member of that parent role.
            self.add_role_membership(role_name, obj_name)
        elif granted_on in _LIVE_GRANT_OBJECT_TYPES and obj_name:
            gkey = (role_name, privilege, obj_name)
            if gkey in self.seen_grant:
                return
            self.seen_grant.add(gkey)
            self.grants.append(
                {
                    "role": role_name,
                    "privilege": privilege,
                    "object_fqn": obj_name,
                    "object_type": granted_on.lower(),
                }
            )

    def add_grant_of(self, role_name: str, r: dict[str, Any]) -> None:
        """One ``SHOW GRANTS OF ROLE`` row: a user membership or a child role."""
        granted_to = str(r.get("granted_to", "") or "").upper()
        grantee = str(r.get("grantee_name", "") or "")
        if not grantee:
            return
        if granted_to == "USER":
            self.add_user_membership(grantee, role_name)
        elif granted_to == "ROLE":
            # The grantee role is a member of this role (grantee → role_name).
            self.add_role_membership(grantee, role_name)


def _role_grants_failure(resource_type: str, warnings_list: list[str]) -> Callable[[Exception], None]:
    """``on_error`` recording a failed live role-grant read as inventory coverage evidence."""
    return lambda exc: _record_snowflake_inventory_failure(
        exc=exc,
        resource_type=resource_type,
        inventory_key="live_role_grants",
        warnings=warnings_list,
    )


def _live_role_grants(conn: Any, role_names: list[str], warnings_list: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Per-role ``SHOW GRANTS TO/OF ROLE`` → object grants + memberships.

    ``SHOW GRANTS TO ROLE "<role>"`` yields the role's privileges: object grants
    (``granted_on`` a TABLE/VIEW/...) become ``grants`` (role HAS_PERMISSION on
    object); ``granted_on=ROLE`` becomes a role→role membership (this role is a
    member of the granted parent role). ``SHOW GRANTS OF ROLE "<role>"`` yields
    who the role is granted to (users → ``{user, role}``; roles → role→role).
    """
    graph = _LiveRoleGraph()
    for role_name in role_names:
        try:
            quoted = _quote_sf_identifier(role_name)
        except ValueError as exc:
            warnings_list.append(f"Skipping unsafe role identifier: {sanitize_error(exc)}")
            continue

        # Privileges this role holds: object grants + role→role parents.
        _for_each_row(
            conn,
            f"SHOW GRANTS TO ROLE {quoted}",
            functools.partial(graph.add_grant_to, role_name),
            _role_grants_failure(f"grants TO role {role_name!r}", warnings_list),
        )

        # Who this role is granted to: users (memberships) + child roles.
        _for_each_row(
            conn,
            f"SHOW GRANTS OF ROLE {quoted}",
            functools.partial(graph.add_grant_of, role_name),
            _role_grants_failure(f"grants OF role {role_name!r}", warnings_list),
        )

    return graph.grants, graph.memberships


def _live_grant_key(g: dict[str, Any]) -> tuple[str, str, str]:
    """Grants keyed by (role, privilege, object_fqn)."""
    return (str(g.get("role", "")), str(g.get("privilege", "")), str(g.get("object_fqn", "")))


def _live_membership_key(m: dict[str, Any]) -> tuple[str, str, str]:
    """Memberships: user→role keyed (user, role); role→role keyed (role, parent)."""
    if m.get("member_type") == "role" or m.get("parent"):
        return ("role", str(m.get("role", "")), str(m.get("parent", "")))
    return ("user", str(m.get("user", "")), str(m.get("role", "")))


def _merge_live_rows(lagged: Any, live: Any, key: Callable[[dict[str, Any]], tuple[str, str, str]]) -> list[dict[str, Any]]:
    """Union lagged then live dict rows by *key*; live overwrites lagged on collision."""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for rows in (lagged, live):
        for row in rows or []:
            if isinstance(row, dict):
                merged[key(row)] = row
    return list(merged.values())


def merge_live_identity_into_object_graph(object_graph: dict[str, Any], live: dict[str, Any]) -> dict[str, Any]:
    """Merge zero-latency SHOW identity into the (lagged) object-graph payload.

    Live SHOW data is preferred over the ACCOUNT_USAGE rows: grants and
    memberships from *live* replace any overlapping lagged rows and are then
    unioned with the remainder, deduped. ``users`` (live-only) are carried
    through so freshly-created users graph immediately. Mutates and returns
    *object_graph*. A non-ok *live* payload is a no-op passthrough.
    """
    if not isinstance(object_graph, dict):
        return object_graph
    if not isinstance(live, dict) or live.get("status") != "ok":
        return object_graph

    object_graph["grants"] = _merge_live_rows(object_graph.get("grants", []), live.get("grants", []), _live_grant_key)
    object_graph["role_memberships"] = _merge_live_rows(
        object_graph.get("role_memberships", []), live.get("role_memberships", []), _live_membership_key
    )

    # Users are live-only (object graph never had them); carry through, deduped.
    if live.get("users"):
        existing = {str(u.get("name", "")) for u in object_graph.get("users", []) or [] if isinstance(u, dict)}
        users = list(object_graph.get("users", []) or [])
        for u in live["users"]:
            if isinstance(u, dict) and str(u.get("name", "")) not in existing:
                users.append(u)
                existing.add(str(u.get("name", "")))
        object_graph["users"] = users

    return object_graph
