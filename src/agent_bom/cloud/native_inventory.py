"""Read-only Modal and NGC metadata; graph and effective-access qualification are separate.

The collectors accept native clients so credentials never enter their reports.
Only allowlisted metadata is retained. A denied or truncated read is incomplete,
never an empty successful snapshot. Neither collector authorizes absent-asset
reconciliation or infers observed communication from configured relationships.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from agent_bom.security import sanitize_text


def _name(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError("Invalid native inventory scope")
    return value


def _mapping(value: Any) -> dict[str, Any]:
    if hasattr(value, "toDict"):
        value = value.toDict()
    if not isinstance(value, dict):
        raise ValueError("Invalid native metadata record")
    return value


def _fields(row: dict[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    return {
        name: sanitize_text(value, max_len=512) if isinstance(value, str) else value
        for name in names
        if (value := row.get(name)) is not None and isinstance(value, (str, bool, int, float))
    }


def _identity_fields(row: dict[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    result = _fields(row, names)
    if not any(result.get(key) for key in ("id", "user_id", "userId", "name", "email")):
        raise ValueError("Native identity has no stable identifier")
    return result


class _Collection:
    def __init__(self, provider: str, scope: str, limit: int) -> None:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Native inventory limit must be between 1 and 1000")
        self.provider, self.scope, self.limit = provider, scope, limit
        self.observed = datetime.now(timezone.utc).isoformat()
        self.coverage: list[dict[str, Any]] = []

    def rows(self, capability: str, read: Callable[[], Any], normalize: Callable[[dict[str, Any]], dict[str, Any]]) -> list[dict[str, Any]]:
        receipt = {
            "provider": self.provider,
            "scope": self.scope,
            "capability": capability,
            "observed_at": self.observed,
            "complete": False,
            "state": "unavailable",
            "persisted": False,
            "evaluated": False,
            "correlated": False,
        }
        self.coverage.append(receipt)
        result: dict[str, dict[str, Any]] = {}
        try:
            raw = read()
            if isinstance(raw, (dict, str, bytes)) or not isinstance(raw, Iterable):
                raise ValueError("Expected a native metadata list")
            for index, item in enumerate(raw):
                if index >= self.limit:
                    receipt["state"] = "truncated"
                    return list(result.values())
                row = normalize(_mapping(item))
                key = str(row.get("id") or json.dumps(row, sort_keys=True))
                if key in result and result[key] != row:
                    receipt["state"] = "conflicting_records"
                    return list(result.values())
                result[key] = row
            receipt.update(complete=True, state="collected" if result else "empty")
        except Exception as exc:  # broad-except: SDK failures must preserve partial metadata without provider exception text
            receipt["state"] = "denied" if isinstance(exc, PermissionError) else "unavailable"
        return list(result.values())

    def resource(self, kind: str, native_id: Any, row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
        native = _name(native_id)
        digest = hashlib.sha256(json.dumps([self.provider, self.scope, kind, native]).encode()).hexdigest()
        return {
            "id": f"{self.provider}:{kind}:{digest}",
            "native_id": native,
            "kind": kind,
            "account_id": self.scope,
            "attributes": _fields(row, fields),
        }

    def report(self, **inventory: Any) -> dict[str, Any]:
        return {
            "schema_version": f"{self.provider}.native-inventory.v1",
            "observed_at": self.observed,
            "status": "ok" if self.coverage and all(r["complete"] for r in self.coverage) else "partial",
            "cloud_inventory": [{"provider": self.provider, "account_id": self.scope, **inventory}],
            "coverage": self.coverage,
            "findings": [],
            "reconcile_absent": False,
            "clean_posture_assertion": False,
            "limitations": [
                "Native metadata collection only; graph ingestion and effective-access evaluation are not qualified by this report.",
                "No runtime communication observations or cross-account trust are inferred from membership or names.",
                "No native incremental feed or full historical snapshot is claimed; absent resources must not be deleted.",
            ],
        }


def collect_modal(
    *, workspace: str, environment: str, workspace_client: Any, read: Callable[[list[str]], Any], limit: int = 100
) -> dict[str, Any]:
    """Use an authenticated Modal Workspace and a fixed read-only CLI transport.

    ``read`` runs the supplied argv with process-local credentials, a deadline
    and an output cap. The environment is explicit; active CLI defaults cannot
    silently select a different environment. Apps are addressed by native ID.
    """
    _name(workspace)
    _name(environment)
    workspace_client.hydrate()
    if workspace_client.name != workspace:
        raise ValueError("Modal credential scope mismatch")
    c = _Collection("modal", workspace + "/" + environment, limit)
    principal_fields = ("name", "user_id", "id", "email", "role", "created_at", "expires_at")
    users = c.rows(
        "workspace_members", lambda: read(["workspace", "members", "list", "--json"]), lambda r: _identity_fields(r, principal_fields)
    )
    services = c.rows(
        "service_users", lambda: read(["workspace", "service-users", "list", "--json"]), lambda r: _identity_fields(r, principal_fields)
    )
    environments = c.rows(
        "environments", lambda: read(["environment", "list", "--json"]), lambda r: _fields(r, ("name", "web_suffix", "active"))
    )

    def role_rows() -> list[dict[str, Any]]:
        roles = _mapping(read(["environment", "roles", "list", environment, "--json"]))
        rows: list[dict[str, Any]] = []
        for key in ("users", "service_users"):
            if not isinstance(roles.get(key), dict):
                raise ValueError("Invalid environment role response")
            rows.extend(
                {"principal": str(name), "principal_type": key, "role": str(role), "environment": environment, "basis": "configured_role"}
                for name, role in roles[key].items()
            )
        return rows

    grants = c.rows("environment_roles", role_rows, lambda r: _fields(r, ("principal", "principal_type", "role", "environment", "basis")))
    return c.report(
        workspace=workspace,
        environment=environment,
        resources=_modal_resources(c, read, environment, limit),
        users=users,
        service_users=services,
        environments=environments,
        grants=grants,
    )


def _modal_resources(c: _Collection, read: Callable[[list[str]], Any], environment: str, limit: int) -> list[dict[str, Any]]:
    apps = c.rows(
        "apps_recent",
        lambda: read(["app", "list", "--env", environment, "--json", "--limit", str(limit + 1)]),
        lambda r: c.resource("app", r.get("app_id"), r, ("description", "state", "tasks", "created_at", "stopped_at")),
    )
    resources = list(apps)
    for app in apps:
        app_id = app["native_id"]

        def functions(app_id: str = app_id) -> list[dict[str, Any]]:
            detail = _mapping(read(["app", "info", app_id, "--env", environment, "--json"]))
            if detail.get("app_id") != app_id or not isinstance(detail.get("functions"), dict):
                raise ValueError("Modal app scope mismatch")
            return [{"name": name, **_mapping(row)} for name, row in detail["functions"].items()]

        functions_found = c.rows(
            "app_functions:" + app_id, functions, lambda r: c.resource("function", r.get("id"), {**r, "app_id": app_id}, ("name", "app_id"))
        )
        resources.extend(functions_found)
        for function in functions_found:
            function_id = function["native_id"]

            def config(function_id: str = function_id, app_id: str = app_id) -> list[dict[str, Any]]:
                row = _mapping(read(["function", "info", function_id, "--env", environment, "--json"]))
                if row.get("object_id") != function_id or row.get("app_id") != app_id:
                    raise ValueError("Modal function scope mismatch")
                return [row]

            details = c.rows(
                "function_config:" + function_id,
                config,
                lambda r: _fields(
                    r,
                    (
                        "name",
                        "app_id",
                        "cpu",
                        "memory_mib",
                        "timeout",
                        "max_retries",
                        "block_network",
                        "restrict_modal_access",
                        "min_containers",
                        "max_containers",
                        "scaledown_window",
                        "buffer_containers",
                    ),
                ),
            )
            if details:
                function["attributes"].update(details[0])
    return resources


def collect_ngc(*, organization: str, client: Any, limit: int = 100) -> dict[str, Any]:
    """Collect the authenticated NGC organization's owned metadata through its SDK.

    NGC Catalog access does not establish NVIDIA infrastructure or compute
    access. Public catalog results are never counted as organization assets.
    Lazy SDK iterators are consumed inside the failure boundary.
    """
    _name(organization)
    who = _mapping(client.users.who(org=organization))
    if who.get("orgName") != organization:
        raise ValueError("NGC credential scope mismatch")
    c = _Collection("ngc", organization, limit)

    def caller_roles() -> list[dict[str, Any]]:
        roles = _mapping(who.get("user")).get("roles")
        if not isinstance(roles, list) or not who.get("userId"):
            raise ValueError("NGC caller roles unavailable")
        result: list[dict[str, Any]] = []
        for assignment in roles:
            assignment = _mapping(assignment)
            if _mapping(assignment.get("org")).get("name") != organization:
                continue
            names = assignment.get("orgRoles")
            if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
                raise ValueError("Invalid NGC caller roles")
            result.extend(
                {"principal": str(who["userId"]), "role": name, "organization": organization, "basis": "configured_caller_role"}
                for name in names
            )
        return result

    grants = c.rows("caller_organization_roles", caller_roles, lambda r: _fields(r, ("principal", "role", "organization", "basis")))
    orgs = c.rows(
        "organization",
        lambda: [client.organization.organization.info(org=organization)],
        lambda r: _fields(r, ("name", "id", "displayName", "type")) if r.get("name") == organization else _mapping(None),
    )
    teams = c.rows(
        "teams",
        lambda: client.organization.team.list(org=organization),
        lambda r: {**_fields(r, ("id", "description")), "name": _name(r.get("name"))},
    )
    users = c.rows(
        "users", lambda: client.users.list(org=organization), lambda r: _identity_fields(r, ("id", "userId", "name", "email", "isActive"))
    )
    return c.report(
        organizations=orgs,
        teams=teams,
        users=users,
        resources=_ngc_resources(c, client, organization, teams),
        caller=_fields(who, ("userId", "orgName", "type")),
        grants=grants,
    )


def _ngc_resources(c: _Collection, client: Any, organization: str, teams: list[dict[str, Any]]) -> list[dict[str, Any]]:
    resources = []
    namespaces = [organization] + [organization + "/" + _name(t.get("name")) for t in teams]
    for namespace in namespaces:

        def image(row: dict[str, Any], namespace: str = namespace) -> dict[str, Any]:
            if row.get("namespace") != namespace:
                raise ValueError("NGC image ownership scope mismatch")
            return c.resource(
                "image", row.get("name"), {**row, "namespace": namespace}, ("name", "namespace", "isPublic", "latestTag", "updatedDate")
            ) | {"id": "ngc:image:" + hashlib.sha256((namespace + "/" + _name(row.get("name"))).encode()).hexdigest()}

        def read_images(namespace: str = namespace) -> Any:
            return client.registry.image.list(pattern=namespace + "/*")

        resources.extend(c.rows("images:" + namespace, read_images, image))

        def model(row: dict[str, Any], namespace: str = namespace) -> dict[str, Any]:
            org = row.get("orgName") or row.get("org")
            if org != organization:
                raise ValueError("NGC model ownership scope mismatch")
            expected_team = namespace.split("/", 1)[1] if "/" in namespace else "no-team"
            if (row.get("teamName") or row.get("team") or "no-team") != expected_team:
                raise ValueError("NGC model team scope mismatch")
            return c.resource("model", row.get("name"), row, ("name", "orgName", "teamName", "displayName", "updatedDate")) | {
                "id": "ngc:model:" + hashlib.sha256((namespace + "/" + _name(row.get("name"))).encode()).hexdigest()
            }

        team = namespace.split("/", 1)[1] if "/" in namespace else "no-team"

        def read_models(namespace: str = namespace, team: str = team) -> Any:
            return client.registry.model.list(target=namespace + "/*", org=organization, team=team)

        resources.extend(c.rows("models:" + namespace, read_models, model))
    return resources
