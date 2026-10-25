"""Overlays applied to a report's graph input before the graph is built.

A dependency-free registry, so the snapshot writer never imports what overlays
it (the same shape as ``graph_commit_hooks``). The API process registers the
operator-advisory overlay when its routes load. An overlay returns the report
unchanged or a copy; it must never mutate the stored report.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

ReportOverlay = Callable[[dict[str, Any], str], dict[str, Any]]

_OVERLAYS: dict[str, ReportOverlay] = {}


def register_graph_input_overlay(name: str, overlay: ReportOverlay) -> None:
    _OVERLAYS[name] = overlay


def registered_overlays() -> list[ReportOverlay]:
    return list(_OVERLAYS.values())


__all__ = ["ReportOverlay", "register_graph_input_overlay", "registered_overlays"]
