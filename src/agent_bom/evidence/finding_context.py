"""Path-derived context is a review aid, never a suppression or severity override."""

from collections.abc import Mapping
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Literal

from agent_bom.core.path_context import classify_path_context

FindingContext = Literal["test", "example", "documentation", "unclassified"]
CONTEXTS: tuple[FindingContext, ...] = ("test", "example", "documentation", "unclassified")


def finding_context(row: Mapping[str, Any]) -> FindingContext:
    evidence = row.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    # A previously projected row has only this safe structural label.
    if not evidence and row.get("path_context") in CONTEXTS:
        return row["path_context"]
    path = evidence.get("repository_relative_path")
    if not path and (evidence.get("iac") is True or row.get("source") in ("IAC_SCAN", "SAST", "SECRET_SCAN")):
        path = evidence.get("file_path")
    if isinstance(path, str) and path:
        normalized = path.replace("\\", "/")
        if PurePosixPath(normalized).is_absolute() or PureWindowsPath(path).drive or ".." in PurePosixPath(normalized).parts:
            return "unclassified"
        return classify_path_context(normalized) or "unclassified"
    context = evidence.get("path_context")
    return context if context in CONTEXTS else "unclassified"
