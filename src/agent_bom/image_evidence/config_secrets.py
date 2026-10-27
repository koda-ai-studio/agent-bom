"""Secrets in an image config: ``ENV`` entries and build history (``created_by``).

``ENV`` values and build arguments are baked into the image config, readable by
anyone who can pull the image. Each entry goes through the filesystem secret
matchers (with entropy detection on secret-named keys), and a credential-named
variable (``*_PASSWORD``, ``*_TOKEN``, ...) holding a literal value is flagged
even when its value has no recognisable format. Only the variable name and the
redacted label are kept — never the value.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agent_bom.constants import is_credential_key
from agent_bom.image_evidence.model import MAX_LABELS, as_list, bounded_string_map
from agent_bom.scanners.secret_lines import is_placeholder_value
from agent_bom.secret_scanner import scan_content
from agent_bom.security import sanitize_text

_CONFIG_PATH = Path("image-config")
_BUILD_ARG_PREFIX_RE = re.compile(r"^\|\d+\s+((?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+)")
_ASSIGNMENT_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)=(\S*)")
_REFERENCE_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")
_MAX_HISTORY = 500


def _literal_secret(key: str, value: str) -> bool:
    if not value or not is_credential_key(key) or key.upper().endswith(("_FILE", "_PATH", "_DIR", "_URL_FILE")):
        return False
    return not (is_placeholder_value(value) or _REFERENCE_RE.match(value) or value.startswith("/"))


def _record(kind: str, location: str, secret_type: str, severity: str, category: str) -> dict[str, Any]:
    return {
        "file": location,
        "line": None,
        "type": secret_type,
        "severity": severity,
        "preview": "[CREDENTIAL_REDACTED]" if category == "credential" else "[SECRET_REDACTED]",
        "category": category,
        "location_kind": kind,
    }


def _scan_entry(kind: str, location: str, text: str, assignments: list[tuple[str, str]]) -> list[dict[str, Any]]:
    found = [
        {**finding.to_dict(), "file": location, "line": None, "location_kind": kind}
        for finding in scan_content(text, _CONFIG_PATH, location, detect_entropy=True)
        if finding.category != "pii"
    ]
    if not found:
        for key, value in assignments:
            if _literal_secret(key, value):
                found.append(_record(kind, location, "Credential-named variable with a literal value", "high", "secret"))
                break
    return found


def _env_entries(config: dict[str, Any]) -> list[str]:
    block = config.get("config") or config.get("Config") or {}
    env = block.get("Env") if isinstance(block, dict) else None
    return [entry for entry in env if isinstance(entry, str)] if isinstance(env, list) else []


def scan_config_secrets(config: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Secret records (redacted) for the image config's ``ENV`` and history entries."""
    if not isinstance(config, dict):
        return []
    secrets: list[dict[str, Any]] = []
    for entry in _env_entries(config):
        key, _, value = entry.partition("=")
        location = f"image config ENV {sanitize_text(key, max_len=120)}"
        secrets.extend(_scan_entry("config_env", location, entry, [(key, value)]))
    history = as_list(config.get("history"))
    for index, item in enumerate(history[:_MAX_HISTORY]):
        created_by = item.get("created_by") if isinstance(item, dict) else None
        if not isinstance(created_by, str) or not created_by:
            continue
        build_args = _BUILD_ARG_PREFIX_RE.match(created_by)
        assignments = _ASSIGNMENT_RE.findall(build_args.group(1)) if build_args else []
        if "ENV " in created_by or "ARG " in created_by:
            assignments += _ASSIGNMENT_RE.findall(created_by)
        location = f"image history step {index + 1}"
        secrets.extend(_scan_entry("history", location, created_by, assignments))
    return secrets


def scan_string_map(raw: object, kind: str, noun: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Labels/annotations as a bounded, sanitized map with secret values replaced, plus their secret records.

    Values are scanned before sanitizing so a credential is reported as a finding,
    not just masked; a flagged value is replaced by the finding's redaction marker.
    """
    values = bounded_string_map(raw)
    if not isinstance(raw, dict):
        return values, []
    secrets: list[dict[str, Any]] = []
    for key in sorted(raw, key=str)[:MAX_LABELS]:
        value = raw[key]
        if not isinstance(value, (str, int, float, bool)):
            continue
        label = sanitize_text(str(key), max_len=200)
        found = _scan_entry(kind, f"image {noun} {label}", f"{key}={value}", [(str(key), str(value))])
        if found:
            values[label] = str(found[0]["preview"])
            secrets.extend(found)
    return values, secrets
