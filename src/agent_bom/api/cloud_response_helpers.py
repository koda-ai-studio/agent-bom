"""Cloud request scope, timeout and response redaction helpers."""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.config import CLOUD_CIS_TIMEOUT_SECONDS, CLOUD_DISCOVERY_TIMEOUT

_logger = logging.getLogger("agent_bom.api.routes.cloud")


_PERMISSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/*-]{0,200}")


_SCOPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/*-]{0,300}")


_AUDIT_ENUM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,40}")


def _clean_tokens(values: Any, pattern: re.Pattern[str], *, cap: int = 500) -> list[str]:
    """Keep only well-formed, structured tokens — the sanitizer barrier.

    Each value is coerced, stripped, and admitted only if it fully matches the
    allowlist ``pattern``. Anything carrying whitespace, control characters, or
    free-form prose (i.e. an exception/stack fragment) is dropped, so no
    exception-derived text can reach the response even if it appears in a
    provider payload field.
    """
    cleaned: list[str] = []
    for value in values or []:
        token = str(value).strip()
        if token and pattern.fullmatch(token):
            cleaned.append(token)
        if len(cleaned) >= cap:
            break
    return cleaned


def _cloud_cis_timeout_seconds() -> float:
    return CLOUD_CIS_TIMEOUT_SECONDS


def _cloud_inventory_timeout_seconds() -> float:
    return max(float(CLOUD_DISCOVERY_TIMEOUT), 1.0)


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _redact_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Strip exception-derived free-form warnings from the external REST response.

    Provider discovery warnings are built from caught exceptions
    (``sanitize_discovery_warning(exc)``), so surfacing them verbatim over REST
    risks exposing backend detail. Keep the ``warnings`` key (REST/MCP shape
    parity) but replace its value with a count-derived, exception-free notice;
    the full warnings remain available via the CLI/MCP surfaces and the server log.
    """
    safe = dict(summary)
    count = len(safe.get("warnings") or [])
    safe["warnings"] = [f"{count} provider discovery warning(s) — run via CLI/MCP or see server logs for detail."] if count else []
    return safe


def _audit_metadata(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll the per-provider read-only discovery envelopes into one audit block.

    Surfaces ``permissions_used`` and the discovery scope so an auditor can verify
    the read-only IAM footprint the scan actually used. Additive — the underlying
    payloads are untouched.
    """
    permissions: list[str] = []
    scopes: list[str] = []
    redaction: list[str] = []
    scan_modes: list[str] = []
    for payload in payloads:
        envelope = payload.get("discovery_envelope")
        if not isinstance(envelope, dict):
            continue
        permissions.extend(_clean_tokens(envelope.get("permissions_used"), _PERMISSION_RE))
        scopes.extend(_clean_tokens(envelope.get("discovery_scope"), _SCOPE_RE))
        redaction.extend(_clean_tokens([envelope.get("redaction_status")], _AUDIT_ENUM_RE))
        scan_modes.extend(_clean_tokens([envelope.get("scan_mode")], _AUDIT_ENUM_RE))
    return {
        "read_only": True,
        "writes_performed": False,
        "scan_modes": sorted(set(scan_modes)),
        "permissions_used": sorted(set(permissions)),
        "discovery_scope": sorted(set(scopes)),
        "redaction_status": sorted(set(redaction)),
        "note": (
            "agent-bom cloud scanning is read-only and agentless. permissions_used lists the exact "
            "read-only IAM actions exercised; no resource is mutated and no secret value is returned."
        ),
    }
