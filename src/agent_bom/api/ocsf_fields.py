"""Shared OCSF resource and finding display-field extraction."""

from typing import Any

from agent_bom.api.trace_collection.normalized_events import tenant_principal
from agent_bom.canonical_ids import canonical_id
from agent_bom.security import sanitize_text


def _object(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _fields(value: object, *keys: str) -> dict[str, str]:
    source = _object(value)
    return {key: sanitize_text(source[key], max_len=200) for key in keys if isinstance(source.get(key), str) and source[key].strip()}


def ocsf_identity_context(event: dict, *, tenant_id: str, source_id: str, event_id: str) -> dict[str, Any]:
    """Retain bounded attribution; a reported actor never establishes an agent binding.

    Principal identifiers use the same tenant-bound digest as trace ingestion.
    Account, device and native session references remain separate from graph ids.
    A synthetic session groups only retries of one event, never unrelated events.
    """
    actor, cloud = _object(event.get("actor")), _object(event.get("cloud"))
    account = _fields(cloud.get("account"), "uid")
    session = _fields(actor.get("session"), "uid")
    user = _object(actor.get("user"))
    principal = user.get("uid")
    safe_user = {"uid_hash": tenant_principal(tenant_id)(principal)} if isinstance(principal, str) and principal else {}
    # Hash the complete identity, not its redacted/truncated display label.
    raw_account = _object(cloud.get("account")).get("uid")
    raw_session = _object(actor.get("session")).get("uid")
    account_scope = raw_account if isinstance(raw_account, str) else ""
    native_session = raw_session if isinstance(raw_session, str) and raw_session.strip() else ""
    return {
        "actor": {"user": safe_user, "session": session},
        "cloud": {**_fields(cloud, "region", "provider"), "account": account},
        "device": _fields(event.get("device"), "uid", "hostname"),
        "session_id": canonical_id("ocsf_session", tenant_id, source_id, account_scope, native_session or event_id),
        "session_id_basis": "reported" if native_session else "event",
    }


def _resource_name(event: dict) -> str:
    resources = event.get("resources")
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, dict) and str(resource.get("name", "")).strip():
                return str(resource["name"]).strip()
    for key in ("resource", "tool_name", "tool"):
        candidate = str(event.get(key, "")).strip()
        if candidate:
            return candidate
    return ""


def _ocsf_finding_message(event: dict) -> str:
    if message := str(event.get("message", "")).strip():
        return message
    finding_info = event.get("finding_info")
    if isinstance(finding_info, dict):
        for key in ("title", "desc", "uid"):
            candidate = str(finding_info.get(key, "")).strip()
            if candidate:
                return candidate
    return str(event.get("class_name", "OCSF event")).strip() or "OCSF event"
