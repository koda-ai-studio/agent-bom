"""Single registry of experimental features.

Every surface that labels something experimental (doctor, storage tiers, the
``/v1/system/health`` payload, docs/EXPERIMENTAL.md) reads this list. Features
marked ``flag_gated`` are OFF until named in ``AGENT_BOM_EXPERIMENTAL`` (a
comma-separated list, ``all`` enables every gated feature); the rest keep the
opt-in they shipped with and are listed here so the label stays consistent.

Import-light by design: stdlib plus ``agent_bom.core.settings`` only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from agent_bom.core.settings import env_list

EXPERIMENTAL_ENV: Final = "AGENT_BOM_EXPERIMENTAL"
EXPERIMENTAL_DOC: Final = "docs/EXPERIMENTAL.md"


@dataclass(frozen=True)
class ExperimentalFeature:
    id: str
    title: str
    surfaces: tuple[str, ...]
    enabled_by: str
    doc: str
    flag_gated: bool = False


EXPERIMENTAL_FEATURES: Final[tuple[ExperimentalFeature, ...]] = (
    ExperimentalFeature(
        id="traces",
        title="Trace pull, trace collection, and trace findings (Langfuse, LangSmith, OTel)",
        surfaces=("api", "mcp", "ui"),
        enabled_by=f"{EXPERIMENTAL_ENV}=traces",
        doc="docs/TRACE_CONNECTIONS.md",
        flag_gated=True,
    ),
    ExperimentalFeature(
        id="storage-snowflake",
        title="Snowflake control-plane stores",
        surfaces=("api",),
        enabled_by="SNOWFLAKE_ACCOUNT set on the control plane",
        doc="docs/STORAGE_BACKENDS.md",
    ),
    ExperimentalFeature(
        id="storage-neptune",
        title="Neptune graph backend",
        surfaces=("api",),
        enabled_by="AGENT_BOM_GRAPH_BACKEND=neptune with AGENT_BOM_EXPERIMENTAL_NEPTUNE_GRAPH=1",
        doc="docs/STORAGE_BACKENDS.md",
    ),
    ExperimentalFeature(
        id="consequence-assessment",
        title="Graph consequence assessment",
        surfaces=("cli", "api", "mcp"),
        enabled_by="always available; output is labelled experimental",
        doc="docs/GRAPH_CONSEQUENCES.md",
    ),
    ExperimentalFeature(
        id="agent-bom-profile-v1",
        title="agent-bom.profile/v1 evidence profile",
        surfaces=("cli", "api"),
        enabled_by="always available; schema is labelled experimental",
        doc="docs/AGENT_BOM_PROFILE.md",
    ),
    ExperimentalFeature(
        id="gpu-psirt-seeds",
        title="AMD and Intel PSIRT curated advisory seeds",
        surfaces=("cli", "api"),
        enabled_by="always available; matches are labelled experimental",
        doc="docs/AI_INFRASTRUCTURE_SCANNING.md",
    ),
    ExperimentalFeature(
        id="mcp-oauth-cimd",
        title="MCP OAuth Client ID Metadata Document support",
        surfaces=("mcp",),
        enabled_by="MCP OAuth configuration; CIMD clients are labelled experimental",
        doc="docs/MCP_OAUTH.md",
    ),
    ExperimentalFeature(
        id="scan-evidence-journey",
        title="Scan evidence journey export",
        surfaces=("cli", "api"),
        enabled_by="always available; export profile is labelled experimental",
        doc="docs/SCAN_EVIDENCE_JOURNEY.md",
    ),
)

_BY_ID: Final = {feature.id: feature for feature in EXPERIMENTAL_FEATURES}


def get_feature(feature_id: str) -> ExperimentalFeature:
    return _BY_ID[feature_id]


def enabled_flags() -> frozenset[str]:
    return frozenset(item.lower() for item in env_list(EXPERIMENTAL_ENV))


def is_enabled(feature_id: str) -> bool:
    feature = _BY_ID[feature_id]
    if not feature.flag_gated:
        return True
    flags = enabled_flags()
    return feature.id in flags or "all" in flags


def disabled_message(feature_id: str) -> str:
    feature = _BY_ID[feature_id]
    return (
        f"{feature.title} is experimental and disabled. "
        f"Enable it with {EXPERIMENTAL_ENV}={feature.id} (comma-separate several). See {feature.doc}."
    )


def feature_status() -> list[dict[str, object]]:
    """Read-only view of every experimental feature and whether it is enabled now."""
    return [
        {
            "id": feature.id,
            "title": feature.title,
            "surfaces": list(feature.surfaces),
            "enabled_by": feature.enabled_by,
            "doc": feature.doc,
            "flag_gated": feature.flag_gated,
            "enabled": is_enabled(feature.id),
        }
        for feature in EXPERIMENTAL_FEATURES
    ]
