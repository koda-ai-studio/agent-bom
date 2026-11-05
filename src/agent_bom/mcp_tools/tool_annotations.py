"""Annotation sets for tools whose behavior differs from the plain read-only default."""

from __future__ import annotations

from mcp_types import ToolAnnotations

# Reads local files or the local store only, and opens no socket.
LOCAL_READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

# Reads its target but keeps a result a later call can read back, and can refresh
# the local advisory database on request. It changes only agent-bom's own state,
# so it is not destructive; each call stores a new result, so it is not idempotent.
KEEPS_LOCAL_RESULT = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)
