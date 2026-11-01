"""Structured field names whose values still require component-level secret checks.

A key in this set exempts its value from the whole-string entropy heuristic
only; every component of the value is still checked against the credential
patterns and the per-component entropy test (``_safe_report_coordinate``), so
an id-shaped key never carries a token out of the report. Keys that name a
credential (``api_key_id``, ``secret_ref``, ...) are deliberately absent.
"""

from __future__ import annotations

import re
from collections.abc import Callable

_REPORT_COORDINATE_KEYS = {
    "id",
    "canonical_id",
    "stable_id",
    "node_id",
    "node_ids",
    "nodeids",
    "edge_id",
    "edge_ids",
    "edgeids",
    "source",
    "target",
    "source_id",
    "target_id",
    "source_node_id",
    "target_node_id",
    "agent_ref",
    "server_ref",
    "mcp_server_ref",
    "target_ref",
    "upstream_ref",
    "bom_ref",
    "purl",
    "package_purl",
    "exposure_path_id",
    "identifier",
    "finding_group_key",
    "finding_node_id",
}
# Manifest / scan-note receipt (``coverage.py``): ``<ecosystem>:<path>`` or ``<ecosystem>-note:<path>``.
_PATH_RECEIPT_RE = re.compile(r"^([a-z][a-z0-9_.-]{0,40}):(.+)$")


def path_receipt_label(value: str, *, is_path: Callable[[str], bool], label: Callable[[object], str]) -> str | None:
    """``pypi-note:/abs/requirements.txt`` -> ``pypi-note:<path:requirements.txt>``; ``None`` for other shapes.

    The path test and the path label are the caller's redaction primitives, so
    this stays free of the security module it serves.
    """
    match = _PATH_RECEIPT_RE.fullmatch(value)
    if match is None or not is_path(match.group(2)):
        return None
    return f"{match.group(1)}:{label(match.group(2))}"


_REPORT_AUTH_MODES = {
    "env-credentials",
    "url-embedded-credentials",
    "network-no-auth-observed",
    "local-stdio",
    "managed_identity",
    "workload_identity",
}
