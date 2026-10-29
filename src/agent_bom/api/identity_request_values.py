"""Existing identity request value parsing and actor attribution."""

from __future__ import annotations

from fastapi import HTTPException, Request

from agent_bom.api.request_contract import require_scalar_str


def _actor(request: Request) -> str:
    return (
        getattr(getattr(request, "state", None), "actor", None) or getattr(getattr(request, "state", None), "api_key_name", None) or "api"
    )


def _tool_name(body: dict) -> str:
    tool_name = require_scalar_str(body, "tool_name", max_length=120)
    if not tool_name:
        raise HTTPException(status_code=400, detail="'tool_name' is required")
    return tool_name


def _ttl_seconds(body: dict, *, default: int = 3600, max_seconds: int = 24 * 3600) -> int:
    try:
        ttl_seconds = int(body.get("ttl_seconds", default))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'ttl_seconds' must be an integer") from exc
    if ttl_seconds < 60:
        raise HTTPException(status_code=400, detail="'ttl_seconds' must be at least 60")
    if ttl_seconds > max_seconds:
        raise HTTPException(status_code=400, detail=f"'ttl_seconds' must be at most {max_seconds}")
    return ttl_seconds


def _str_list(body: dict, key: str, *, max_items: int = 200, max_len: int = 120) -> list[str]:
    raw = body.get(key, [])
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail=f"'{key}' must be a list of strings")
    return [str(v).strip()[:max_len] for v in raw if str(v).strip()][:max_items]


def _bool(body: dict, key: str) -> bool:
    raw = body.get(key, False)
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in {"true", "1", "yes", "on"}


def _int_list(body: dict, key: str, *, lo: int, hi: int) -> list[int]:
    raw = body.get(key, [])
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail=f"'{key}' must be a list of integers")
    out: list[int] = []
    for v in raw:
        try:
            n = int(v)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"'{key}' must contain integers") from exc
        if not (lo <= n <= hi):
            raise HTTPException(status_code=400, detail=f"'{key}' values must be between {lo} and {hi}")
        out.append(n)
    return out


# ── Scoped delegation tokens (multi-agent handoff) ──────────────────────────────
def _delegation_scopes(body: dict) -> list[str]:
    raw = body.get("scopes", [])
    if not isinstance(raw, list) or not raw:
        raise HTTPException(status_code=400, detail="'scopes' must be a non-empty list of capability strings")
    scopes = [str(v).strip()[:200] for v in raw if str(v).strip()][:100]
    if not scopes:
        raise HTTPException(status_code=400, detail="'scopes' must contain at least one non-empty capability")
    return scopes
