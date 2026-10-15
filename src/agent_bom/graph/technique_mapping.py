"""Typed MITRE ATT&CK / ATLAS technique mappings attached to attack-path hops."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TechniqueMapping:
    """A typed MITRE ATT&CK / ATLAS technique mapped to one hop of an attack path.

    These are *potential* techniques derived from the graph's observed evidence
    (the hop's edge relationship type + the target node's entity type + the
    edge's evidence), NOT a claim that the technique was detected being used.
    ``technique_id`` / ``tactics`` always resolve against the bundled catalog
    (see :mod:`agent_bom.graph.attack_path_mitre`); a hop whose evidence maps to
    no known technique is simply left without a mapping (fail-closed).
    """

    hop_index: int  # 0-based position in the kill-chain edge sequence
    technique_id: str  # e.g. "T1078" (ATT&CK) or "AML.T0053" (ATLAS)
    technique_name: str = ""
    catalog: str = "attack"  # "attack" | "atlas"
    tactics: list[str] = field(default_factory=list)
    provenance: str = ""  # observed evidence that produced the mapping
    confidence: float | None = None  # 0..1 mapping confidence, unavailable without a basis
    evidence_basis: str | None = None

    def __post_init__(self) -> None:
        if self.evidence_basis not in {"observed", "runtime_observed", "inferred", "modeled"}:
            self.evidence_basis = None
            self.confidence = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hop_index": self.hop_index,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "catalog": self.catalog,
            "tactics": self.tactics,
            "provenance": self.provenance,
            "confidence": self.confidence if self.evidence_basis else None,
            "evidence_basis": self.evidence_basis,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TechniqueMapping:
        return cls(
            hop_index=int(data.get("hop_index", 0)),
            technique_id=data["technique_id"],
            technique_name=data.get("technique_name", ""),
            catalog=data.get("catalog", "attack"),
            tactics=list(data.get("tactics", [])),
            provenance=data.get("provenance", ""),
            confidence=float(data["confidence"]) if data.get("confidence") is not None and data.get("evidence_basis") else None,
            evidence_basis=data.get("evidence_basis"),
        )


def technique_mappings_from_json(raw: object) -> list["TechniqueMapping"]:
    """Decode persisted ``technique_mappings`` JSON into typed objects.

    Tolerant of legacy rows: ``None`` / empty / malformed values yield ``[]``.
    """
    if not raw:
        return []
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return []
    else:
        data = raw
    if not isinstance(data, list):
        return []
    return [TechniqueMapping.from_dict(m) for m in data if isinstance(m, dict)]
