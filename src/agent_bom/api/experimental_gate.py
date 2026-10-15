"""API surface for the experimental-feature registry (agent_bom.core.experimental)."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from agent_bom.api.models import HealthResponse
from agent_bom.core.experimental import disabled_message, is_enabled


class ExperimentalFeatureHealth(BaseModel):
    id: str
    title: str
    surfaces: list[str]
    enabled_by: str
    doc: str
    flag_gated: bool
    enabled: bool | None = Field(description="Whether the flag enables it now; null when the feature has its own opt-in.")


class SystemHealthResponse(HealthResponse):
    experimental_features: list[ExperimentalFeatureHealth] = Field(default_factory=list)


def ensure_experimental(feature_id: str) -> None:
    """404 with an enable hint, so a disabled feature never answers with silent empties."""
    if not is_enabled(feature_id):
        raise HTTPException(status_code=404, detail=disabled_message(feature_id))


def require_experimental(feature_id: str) -> Any:
    def _dependency() -> None:
        ensure_experimental(feature_id)

    return Depends(_dependency)
