"""Bounded source labels that omit private filesystem parents."""

import re
from collections.abc import Mapping
from typing import Any

from agent_bom.security import sanitize_path_label


def iac_source_label(name: str, evidence: Any) -> str | None:
    marker = sanitize_path_label(name)
    match = re.fullmatch(r"<path:([^<>/\\]{1,80})>", marker)
    label = match[1] if match is not None else None
    if label in {"path", ".", ".."}:
        label = None
    line = evidence.get("line_number") if isinstance(evidence, Mapping) else None
    if label and isinstance(line, int) and not isinstance(line, bool) and 0 < line <= 2**31 - 1:
        label = f"{label}:{line}"
    return label


def readable_asset_name(name: Any) -> Any:
    """Readable label for internal surface identities shown in answers.

    ``repo-deps:<dir>`` (repository dependency manifests) and ``fs:<path>``
    (a filesystem scan, its path pseudonymized) are identities, not names a
    reader recognizes. Ids keep the identity; answers show this label.
    """
    if not isinstance(name, str):
        return name
    if name.startswith("repo-deps:"):
        scope = name.removeprefix("repo-deps:")
        return "project dependencies" if scope in {"", ".", "root"} else f"project dependencies ({scope})"
    if name.startswith("fs:"):
        return "filesystem packages"
    return name


def readable_asset_names(value: Any) -> Any:
    return [readable_asset_name(item) for item in value] if isinstance(value, list) else readable_asset_name(value)
