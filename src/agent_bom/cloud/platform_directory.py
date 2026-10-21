"""Bounded organization membership reads; configured grants are not effective access."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from agent_bom.cloud.management_http import read_json
from agent_bom.security import sanitize_text

MAX_PAGES = 20
MAX_RECORDS = 2000
MAX_BYTES = 2 * 1024 * 1024


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError("Invalid directory field")
    return sanitize_text(value)


def _scope(value: str, provider: str) -> str:
    pattern = r"[a-z]{20}" if provider == "supabase" else r"team_[A-Za-z0-9_-]{1,128}"
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError("Invalid directory scope")
    return value


def _id(provider: str, account: str, kind: str, native: str) -> str:
    return f"{kind}:{provider}:" + hashlib.sha256(json.dumps([account, native]).encode()).hexdigest()


def _receipt(provider: str, account: str, capability: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "account_id": account,
        "capability": capability,
        "state": "not_attempted",
        "complete": False,
        "read": False,
        "ingested": False,
        "persisted": False,
        "graph_supported": False,
        "evaluated": False,
        "correlated": False,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "pages_read": 0,
    }


def _read(client: httpx.Client, url: str, token: str, receipt: dict[str, Any], **params: Any) -> Any:
    payload, state = read_json(client, url, token, max_bytes=MAX_BYTES, params=params or None)
    receipt.update(state=state, read=state == "read")
    if state == "read":
        receipt["pages_read"] += 1
    return payload


def _complete(receipt: dict[str, Any], rows: list[Any]) -> None:
    receipt.update(state="collected" if rows else "empty", complete=True, ingested=True)


def _member(row: Any, provider: str, account: str) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError("Invalid member")
    raw_native = row.get("user_id" if provider == "supabase" else "uid")
    if not isinstance(raw_native, str):
        raise ValueError("Invalid member identity")
    native = _text(raw_native)
    role = _text(row.get("role_name" if provider == "supabase" else "role"))
    result = {
        "id": _id(provider, account, "user", raw_native),
        "native_id": native,
        "account_id": account,
        "provider": provider,
        "role": role,
    }
    for source, target in (("user_name" if provider == "supabase" else "username", "name"), ("email", "email")):
        if row.get(source) is not None:
            result[target] = _text(row[source])
    for source, target in (("mfa_enabled" if provider == "supabase" else "mfaEnabled", "mfa_enabled"), ("confirmed", "confirmed")):
        if source in row:
            if type(row[source]) is not bool:
                raise ValueError("Invalid membership flag")
            result[target] = row[source]
    return result


def _members(rows: Any, provider: str, account: str) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise ValueError("Invalid member collection")
    found: dict[str, dict[str, Any]] = {}
    for raw in rows:
        row = _member(raw, provider, account)
        if row["id"] in found and found[row["id"]] != row:
            raise ValueError("Conflicting member identity")
        found[row["id"]] = row
    return list(found.values())


def _report(provider: str, account: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "account_id": account,
        "name": account,
        "identities": [],
        "grants": [],
        "project_refs": [],
        "coverage": [],
        "cross_account_trust": {"state": "not_collected", "evidence": []},
        "observed_communication": {"state": "not_collected", "evidence": []},
        "service_identities": {"state": "not_collected", "identities": []},
    }


def _grants(report: dict[str, Any]) -> None:
    for member in report["identities"]:
        report["grants"].append(
            {
                "id": _id(report["provider"], report["account_id"], "grant", member["id"] + ":" + member["role"]),
                "principal_id": member["id"],
                "account_id": report["account_id"],
                "role": member["role"],
                "basis": "configured_membership",
                "effective_access": "not_evaluated",
                "confirmed": member.get("confirmed"),
            }
        )


def _organization(client: httpx.Client, token: str, url: str, report: dict[str, Any]) -> bool:
    receipt = _receipt(report["provider"], report["account_id"], "organization")
    report["coverage"].append(receipt)
    data = _read(client, url, token, receipt)
    if receipt["state"] != "read":
        return False
    try:
        if not isinstance(data, dict) or data.get("id") != report["account_id"]:
            raise ValueError("Organization scope mismatch")
        report["name"] = _text(data.get("name"))
        _complete(receipt, [data])
        return True
    except (ValueError, TypeError):
        receipt["state"] = "invalid_response"
        return False


def _supabase_projects(client: httpx.Client, token: str, url: str, receipt: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    offset = 0
    expected_count = None
    for _ in range(MAX_PAGES):
        data = _read(client, url, token, receipt, offset=offset, limit=100)
        if receipt["state"] != "read":
            return refs
        try:
            rows, pagination = data["projects"], data["pagination"]
            count, limit, returned_offset = (pagination[key] for key in ("count", "limit", "offset"))
            if not isinstance(rows, list) or any(type(v) is not int for v in (count, limit, returned_offset)):
                raise ValueError("Invalid project pagination")
            if count < 0 or limit < 1 or returned_offset != offset or len(rows) > limit:
                raise ValueError("Invalid project continuation")
            if expected_count is not None and expected_count != count:
                raise ValueError("Project count changed during collection")
            expected_count = count
            page = [_scope(row["ref"], "supabase") for row in rows]
            if len(set(refs + page)) != len(refs + page) or len(refs) + len(page) > count:
                raise ValueError("Repeated or inconsistent project page")
            if len(refs) + len(page) > 50:
                receipt["state"] = "record_limit"
                return refs
            refs.extend(page)
            offset += len(page)
            if offset == count:
                _complete(receipt, refs)
                return refs
            if not page:
                raise ValueError("Empty continued project page")
        except (KeyError, ValueError, TypeError):
            receipt["state"] = "invalid_response"
            return refs
    receipt["state"] = "page_limit"
    return refs


def collect_supabase_directory(*, organization: str, token: str, client: httpx.Client) -> dict[str, Any]:
    """Read an explicit organization, its project references and dashboard members."""
    account = _scope(organization, "supabase")
    report = _report("supabase", account)
    url = "https://api.supabase.com/v1/organizations/" + account
    if not _organization(client, token, url, report):
        return report
    members = _receipt("supabase", account, "organization_members")
    projects = _receipt("supabase", account, "organization_projects")
    report["coverage"].extend([members, projects])
    data = _read(client, url + "/members", token, members)
    if members["state"] == "read":
        try:
            report["identities"] = _members(data, "supabase", account)
            _complete(members, report["identities"])
        except (ValueError, TypeError):
            members["state"] = "invalid_response"
    report["project_refs"] = _supabase_projects(client, token, url + "/projects", projects)
    _grants(report)
    return report


def _vercel_members(client: httpx.Client, token: str, url: str, receipt: dict[str, Any], account: str) -> list[dict[str, Any]]:
    rows: list[Any] = []
    cursor = None
    for _ in range(MAX_PAGES):
        params = {"limit": 100, **({"until": cursor} if cursor is not None else {})}
        data = _read(client, url, token, receipt, **params)
        if receipt["state"] != "read":
            return _members(rows, "vercel", account)
        try:
            page, pagination = data["members"], data["pagination"]
            if not isinstance(page, list) or not isinstance(pagination, dict):
                raise ValueError("Invalid member page")
            if len(rows) + len(page) > MAX_RECORDS:
                receipt["state"] = "record_limit"
                return _members(rows, "vercel", account)
            updated = _members(rows + page, "vercel", account)
            next_cursor = pagination.get("next")
            total = data.get("totalCount")
            if "totalCount" in data and (type(total) is not int or total < 0):
                raise ValueError("Invalid membership total")
            if "hasNext" in pagination and type(pagination["hasNext"]) is not bool:
                raise ValueError("Invalid continuation flag")
            if pagination.get("hasNext") is True and next_cursor is None:
                raise ValueError("Missing continuation cursor")
            terminal = ("next" in pagination and next_cursor is None) or pagination.get("hasNext") is False
            if type(total) is int and total >= 0 and total == len(updated) and next_cursor is None:
                terminal = True
            if terminal:
                if next_cursor is not None or (type(total) is int and total != len(updated)):
                    raise ValueError("Inconsistent membership total")
                _complete(receipt, updated)
                return updated
            if type(next_cursor) is not int or next_cursor < 0 or (cursor is not None and next_cursor >= cursor) or not page:
                raise ValueError("Unproven membership continuation")
            rows.extend(page)
            cursor = next_cursor
        except (KeyError, ValueError, TypeError):
            receipt["state"] = "invalid_response"
            return _members(rows, "vercel", account)
    receipt["state"] = "page_limit"
    return _members(rows, "vercel", account)


def collect_vercel_directory(*, team: str, token: str, client: httpx.Client) -> dict[str, Any]:
    """Read one explicit team's metadata and bounded membership pages."""
    account = _scope(team, "vercel")
    report = _report("vercel", account)
    if not _organization(client, token, "https://api.vercel.com/v2/teams/" + account, report):
        return report
    members = _receipt("vercel", account, "organization_members")
    report["coverage"].append(members)
    report["identities"] = _vercel_members(client, token, "https://api.vercel.com/v3/teams/" + account + "/members", members, account)
    _grants(report)
    return report
