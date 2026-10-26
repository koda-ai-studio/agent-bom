"""A traversal coverage receipt is a coordinate, not a secret: it must survive redaction intact."""

from __future__ import annotations

import hashlib

import pytest

from agent_bom.security import sanitize_sensitive_payload

_REASONS = ["scope_excluded_dir", "symlink_outside_root", "depth_limit", "directory_read_error", "repository_ignore"]


@pytest.mark.parametrize("seed", range(40))
def test_filesystem_discovery_release_token_is_never_redacted(seed: int) -> None:
    root_id = hashlib.sha256(f"/workspaces/proj-{seed}".encode()).hexdigest()[:16]
    for reason in _REASONS:
        release = f"filesystem-discovery:{root_id}:{reason}"
        assert sanitize_sensitive_payload({"release": release}) == {"release": release}


def test_exemption_is_narrow() -> None:
    opaque = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6"
    assert sanitize_sensitive_payload({"release": opaque}) == {"release": "***REDACTED***"}
    assert sanitize_sensitive_payload({"release": f"filesystem-discovery:{opaque}:x"})["release"] == "***REDACTED***"
