"""Bound and redact audit labels and metadata before durable persistence."""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from agent_bom.security import sanitize_path_label, sanitize_sensitive_payload

_AUDIT_DETAIL_KEY_RE = re.compile(r"[^a-zA-Z0-9_.:-]+")


_MAX_AUDIT_DETAIL_KEYS = 64


_MAX_AUDIT_DETAIL_KEY_LENGTH = 96


_MAX_AUDIT_DETAIL_STRING_LENGTH = 2048


_MAX_AUDIT_DETAIL_COLLECTION_ITEMS = 32


_MAX_AUDIT_DETAIL_DEPTH = 4


_MAX_AUDIT_DETAILS_JSON_BYTES = 16 * 1024


def _sanitize_detail_key(key: object) -> str:
    cleaned = _AUDIT_DETAIL_KEY_RE.sub("_", str(key).strip())[:_MAX_AUDIT_DETAIL_KEY_LENGTH].strip("._:-")
    cleaned = cleaned.strip("_")
    return cleaned or "detail"


def _sanitize_detail_value(value: object, *, depth: int = 0) -> object:
    if depth >= _MAX_AUDIT_DETAIL_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        sanitized = sanitize_sensitive_payload(value, max_str_len=_MAX_AUDIT_DETAIL_STRING_LENGTH)
        text = str(sanitized).replace("\r", " ").replace("\n", " ").replace("\t", " ")
        return text[:_MAX_AUDIT_DETAIL_STRING_LENGTH]
    if isinstance(value, dict):
        out: dict[str, object] = {}
        for index, (raw_key, raw_value) in enumerate(value.items()):
            if index >= _MAX_AUDIT_DETAIL_COLLECTION_ITEMS:
                out["_truncated"] = True
                break
            clean_key = _sanitize_detail_key(raw_key)
            out[clean_key] = _sanitize_detail_value(
                sanitize_sensitive_payload(raw_value, key=clean_key, max_str_len=_MAX_AUDIT_DETAIL_STRING_LENGTH),
                depth=depth + 1,
            )
        return out
    if isinstance(value, list | tuple | set):
        items = list(value)
        list_out = [
            _sanitize_detail_value(sanitize_sensitive_payload(item, max_str_len=_MAX_AUDIT_DETAIL_STRING_LENGTH), depth=depth + 1)
            for item in items[:_MAX_AUDIT_DETAIL_COLLECTION_ITEMS]
        ]
        if len(items) > _MAX_AUDIT_DETAIL_COLLECTION_ITEMS:
            list_out.append("[truncated]")
        return list_out
    return str(sanitize_sensitive_payload(value, max_str_len=_MAX_AUDIT_DETAIL_STRING_LENGTH))[:_MAX_AUDIT_DETAIL_STRING_LENGTH]


def sanitize_audit_details(details: dict[str, object]) -> dict[str, object]:
    """Bound audit metadata shape and size before persistence/export."""
    sanitized: dict[str, object] = {}
    for index, (raw_key, raw_value) in enumerate(details.items()):
        if index >= _MAX_AUDIT_DETAIL_KEYS:
            sanitized["_truncated"] = True
            break
        clean_key = _sanitize_detail_key(raw_key)
        sanitized[clean_key] = _sanitize_detail_value(
            sanitize_sensitive_payload(raw_value, key=clean_key, max_str_len=_MAX_AUDIT_DETAIL_STRING_LENGTH)
        )

    encoded = json.dumps(sanitized, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    if len(encoded) <= _MAX_AUDIT_DETAILS_JSON_BYTES:
        return sanitized

    tenant_id = sanitized.get("tenant_id", "default")
    return {
        "tenant_id": str(tenant_id)[:_MAX_AUDIT_DETAIL_STRING_LENGTH],
        "_truncated": True,
        "_original_bytes": len(encoded),
    }


def _safe_audit_label(value: object, *, key: str, default: str = "") -> str:
    """Return a durable tier-A label for top-level actor/resource fields."""
    if value in (None, ""):
        return default
    text = str(sanitize_sensitive_payload(value, key=key, max_str_len=256) or "")
    if not text:
        return default
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        return f"<url:{parsed.hostname or 'host'}>"
    if text.startswith(("/", "~/")) or re.match(r"^[A-Za-z]:[\\/]", text):
        return sanitize_path_label(text)
    return text[:256]
