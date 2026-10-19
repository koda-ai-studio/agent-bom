"""Entry-point helpers for the agent-bom MCP server."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def create_smithery_server(factory: Callable[[], Any]) -> Any:
    """Retain the registry factory without the SDK-1-only Smithery decorator.

    The stdio entrypoint needs the MCP server itself. Hosted registration uses
    the authenticated HTTP endpoint documented in docs/RELEASE_VERIFICATION.md.
    """
    return factory()
