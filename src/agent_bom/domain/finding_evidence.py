"""Bounded evidence projection and sanitization for findings."""

from __future__ import annotations


def _package_occurrence_evidence(occurrence: object) -> dict[str, object]:
    """Return layer/package provenance in a stable dict shape."""
    if hasattr(occurrence, "to_dict"):
        raw = occurrence.to_dict()
        if isinstance(raw, dict):
            return raw
    return {
        "layer_index": getattr(occurrence, "layer_index", None),
        "layer_id": getattr(occurrence, "layer_id", None),
        "layer_path": getattr(occurrence, "layer_path", None),
        "package_path": getattr(occurrence, "package_path", None),
        "created_by": getattr(occurrence, "created_by", None),
        "dockerfile_instruction": getattr(occurrence, "dockerfile_instruction", None),
    }


def _evidence_payload(value: object) -> object:
    """Normalize common model objects before recursive evidence sanitization."""
    if isinstance(value, dict):
        return {str(key): _evidence_payload(child) for key, child in value.items()}
    if isinstance(value, list | tuple | set):
        return [_evidence_payload(item) for item in value]
    if hasattr(value, "to_dict"):
        raw = value.to_dict()
        if isinstance(raw, dict):
            return _evidence_payload(raw)
    if hasattr(value, "name"):
        payload: dict[str, object] = {"name": getattr(value, "name", None)}
        for attr in ("version", "ecosystem", "hop", "id", "transport", "url", "command", "args"):
            if hasattr(value, attr):
                payload[attr] = getattr(value, attr)
        return payload
    return value


def _evidence_key_looks_sensitive(key: object | None) -> bool:
    if key is None:
        return False
    from agent_bom.security import _key_looks_sensitive

    return _key_looks_sensitive(key)


def _evidence_key_looks_like_url(key: object | None) -> bool:
    if key is None:
        return False
    key_text = str(key).lower()
    return key_text in {"url", "uri", "endpoint", "webhook"} or key_text.endswith(("_url", "_uri", "_endpoint", "_webhook"))


def _evidence_key_looks_like_path(key: object | None) -> bool:
    if key is None:
        return False
    key_text = str(key).lower()
    return (
        "path" in key_text
        or key_text in {"cwd", "workspace", "dir", "directory"}
        or key_text.endswith(("_dir", "_directory", "_cwd", "_workspace"))
    )


def _sanitized_evidence_value(value: object, *, key: object | None = None, depth: int = 0) -> object:
    from agent_bom.security import sanitize_path_label, sanitize_sensitive_payload, sanitize_text, sanitize_url

    if depth >= 8:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        if _evidence_key_looks_sensitive(key):
            return "***REDACTED***"
        if _evidence_key_looks_like_url(key):
            return sanitize_url(value)
        if _evidence_key_looks_like_path(key):
            return sanitize_path_label(value)
        return sanitize_text(value)
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        for raw_key, raw_value in value.items():
            clean_key = sanitize_text(raw_key, max_len=200)
            sanitized[clean_key] = _sanitized_evidence_value(raw_value, key=clean_key, depth=depth + 1)
        return sanitized
    if isinstance(value, list | tuple | set):
        return [_sanitized_evidence_value(item, key=key, depth=depth + 1) for item in list(value)]
    return sanitize_sensitive_payload(value)


def _sanitized_evidence_field(value: object) -> object:
    return _sanitized_evidence_value(_evidence_payload(value))
