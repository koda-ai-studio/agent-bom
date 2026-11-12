"""Exact release contract a deployed MCP server card must satisfy.

Dependency-free so release workflows can run it from a bare checkout.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["expected_tool_names_for_card", "load_tool_names", "validate_server_card_release"]


def _card_auth_schemes(payload: dict[str, Any]) -> list[str]:
    authentication = payload.get("authentication")
    schemes = authentication.get("schemes") if isinstance(authentication, dict) else None
    return [scheme for scheme in schemes if isinstance(scheme, str)] if isinstance(schemes, list) else []


def expected_tool_names_for_card(
    payload: dict[str, Any], *, full: list[str] | None, read_only: list[str] | None
) -> tuple[list[str] | None, bool]:
    """Pick the exact tool set the card's auth mode registers.

    An OAuth server registers only the read-only subset of its profile, so it is
    held to that subset; any other card is held to the full default profile.
    """
    if "oauth2" not in _card_auth_schemes(payload):
        return full, False
    if full is not None and read_only is None:
        raise ValueError("OAuth server card requires the expected read-only tool set")
    return read_only, True


def validate_server_card_release(
    payload: dict[str, Any],
    *,
    expected_version: str,
    expected_tool_count: int | None = None,
    expected_tool_names: list[str] | None = None,
    expected_read_only_tool_names: list[str] | None = None,
    expected_auth_scheme: str | None = None,
) -> dict[str, Any]:
    """Require exact version, auth mode, tool inventory, and usable schemas for a release."""

    server_info = payload.get("serverInfo")
    if not isinstance(server_info, dict) or server_info.get("version") != expected_version:
        deployed = server_info.get("version") if isinstance(server_info, dict) else None
        raise ValueError(f"server-card version mismatch: deployed={deployed!r} expected={expected_version!r}")

    schemes = _card_auth_schemes(payload)
    if expected_auth_scheme is not None and schemes != [expected_auth_scheme]:
        raise ValueError(f"server-card authentication scheme mismatch: deployed={schemes!r} expected={[expected_auth_scheme]!r}")
    selected, oauth = expected_tool_names_for_card(payload, full=expected_tool_names, read_only=expected_read_only_tool_names)
    if selected is not None:
        expected_tool_count = len(selected)
    if expected_tool_count is None:
        raise ValueError("server-card release check requires an expected tool inventory")

    tools = payload.get("tools")
    if not isinstance(tools, list) or len(tools) != expected_tool_count:
        actual = len(tools) if isinstance(tools, list) else None
        kind = "count" if selected is None else "set"
        detail = "" if selected is None else _tool_set_detail(tools, selected)
        raise ValueError(f"server-card tool {kind} mismatch: deployed={actual!r} expected={expected_tool_count}{detail}")

    names: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"].strip():
            raise ValueError("server-card tool schema is missing a non-empty name")
        if not isinstance(tool.get("inputSchema"), dict):
            raise ValueError(f"server-card tool schema is missing inputSchema for {tool['name']!r}")
        names.append(tool["name"])
    if len(set(names)) != len(names):
        raise ValueError("server-card tool schema contains duplicate tool names")
    if selected is not None and set(names) != set(selected):
        raise ValueError(f"server-card tool set mismatch{_tool_set_detail(tools, selected)}")
    if oauth:
        writable = sorted(
            tool["name"]
            for tool in tools
            if not isinstance(tool.get("annotations"), dict) or tool["annotations"].get("readOnlyHint") is not True
        )
        capabilities = payload.get("capabilities")
        if writable or not isinstance(capabilities, dict) or capabilities.get("read_only") is not True:
            raise ValueError(f"OAuth server card exposes non-read-only tools: {writable!r}")
    return payload


def _tool_set_detail(tools: object, expected: list[str]) -> str:
    deployed = {tool.get("name") for tool in tools if isinstance(tool, dict)} if isinstance(tools, list) else set()
    unexpected = sorted(str(name) for name in deployed - set(expected))
    missing = sorted(set(expected) - deployed)
    return f" (unexpected={unexpected!r} missing={missing!r})"


def load_tool_names(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as handle:
            names = json.load(handle)
    except OSError as exc:
        raise ValueError(f"expected tool-name file is unreadable: {path}") from exc
    if not isinstance(names, list) or not names or any(not isinstance(name, str) or not name for name in names):
        raise ValueError(f"expected tool-name file must be a non-empty JSON list of names: {path}")
    if len(set(names)) != len(names):
        raise ValueError(f"expected tool-name file contains duplicate names: {path}")
    return names
