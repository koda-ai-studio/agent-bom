"""Serving-endpoint evidence block for one agent card in the HTML report."""

from __future__ import annotations

from typing import Any

from agent_bom.output.html._common import _esc

_SEP = " &middot; "


def _reported(value: Any, label: str) -> str:
    return _esc(value) if value not in (None, "") else f"{label} not reported"


def _runtime(runtime: dict[str, Any]) -> str:
    name = _esc(runtime.get("name") or "runtime")
    version = _esc(runtime["version"]) if runtime.get("version") else "version not reported"
    return f"{name} {version} ({_esc(runtime.get('identity') or 'declared')})"


def _model(model: dict[str, Any]) -> str:
    parts = [
        _reported(model.get("served_name"), "name"),
        f"artifact {_esc(model['artifact_ref'])}" if model.get("artifact_ref") else "artifact not reported",
        f"digest {_esc(model['digest'])}" if model.get("digest") else "digest not reported",
        f"version {_esc(model['version'])}" if model.get("version") else "version not reported",
    ]
    if model.get("state"):
        parts.append(f"state {_esc(model['state'])}")
    return _SEP.join(parts)


def _collection(collection: dict[str, Any]) -> str:
    parts = [
        _esc(collection.get("status") or "unknown"),
        _esc(collection.get("completeness") or "unknown"),
        f"observed {_esc(collection.get('observed_at') or 'unknown')}",
        f"request {_esc(collection.get('request_identity') or 'anonymous')}",
    ]
    if collection.get("detail"):
        parts.append(_esc(collection["detail"]))
    return _SEP.join(parts)


def _not_collected(evidence: dict[str, Any]) -> str:
    settings = ", ".join(_esc(item) for item in (evidence.get("collection") or {}).get("not_collected") or [])
    unknown = ", ".join(_esc(key) for key, value in (evidence.get("unknown_identities") or {}).items() if value is None)
    lines = [f"settings: {settings}" if settings else "", f"identities: {unknown}" if unknown else ""]
    return "<br>".join(line for line in lines if line) or "nothing listed"


def serving_evidence_html(metadata: dict[str, Any] | None) -> str:
    """Render ``metadata.serving_evidence`` as labelled rows, or ``""`` when absent."""
    evidence = (metadata or {}).get("serving_evidence")
    if not isinstance(evidence, dict) or not evidence:
        return ""
    rows = [
        ("Runtime", _runtime(evidence.get("runtime") or {})),
        ("Endpoint", _reported((evidence.get("endpoint") or {}).get("url"), "endpoint")),
        ("Model artifact", _model(evidence.get("model") or {})),
        ("Collection", _collection(evidence.get("collection") or {})),
        ("Not collected", _not_collected(evidence)),
    ]
    body = "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows)
    return f'<dl class="serving-evidence" aria-label="Serving endpoint evidence">{body}</dl>'
