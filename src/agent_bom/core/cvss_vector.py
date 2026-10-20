"""CVSS 3.x and 4.0 base vectors decoded into plain words.

Metric names and values follow the FIRST CVSS v3.1 and v4.0 specifications.
A vector that is not a complete, well-formed base vector decodes to ``None``:
a partial reading would let a caller describe an attack the record does not
support.
"""

from __future__ import annotations

from typing import Any

_AV = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
_AC = {"L": "low", "H": "high"}
_AT = {"N": "none", "P": "present"}
_PR = {"N": "none", "L": "low", "H": "high"}
_UI_V3 = {"N": "none", "R": "required"}
_UI_V4 = {"N": "none", "P": "passive", "A": "active"}
_SCOPE = {"U": "unchanged", "C": "changed"}
_CIA = {"N": "none", "L": "low", "H": "high"}

_V3_REQUIRED = {"AV": _AV, "AC": _AC, "PR": _PR, "UI": _UI_V3, "S": _SCOPE, "C": _CIA, "I": _CIA, "A": _CIA}
_V4_REQUIRED = {
    "AV": _AV,
    "AC": _AC,
    "AT": _AT,
    "PR": _PR,
    "UI": _UI_V4,
    "VC": _CIA,
    "VI": _CIA,
    "VA": _CIA,
    "SC": _CIA,
    "SI": _CIA,
    "SA": _CIA,
}


def _metrics(parts: list[str]) -> dict[str, str] | None:
    metrics: dict[str, str] = {}
    for part in parts:
        key, sep, value = part.partition(":")
        if not sep or not key or not value or key in metrics:
            return None
        metrics[key] = value
    return metrics


def _decoded(metrics: dict[str, str], required: dict[str, dict[str, str]]) -> dict[str, str] | None:
    words: dict[str, str] = {}
    for key, table in required.items():
        word = table.get(metrics.get(key, ""))
        if word is None:
            return None
        words[key] = word
    return words


def decode_cvss_vector(vector: str | None) -> dict[str, Any] | None:
    """Decode a CVSS 3.0, 3.1 or 4.0 base vector, or ``None`` when it is not one."""
    if not isinstance(vector, str):
        return None
    raw = vector.strip()
    prefix, _, rest = raw.partition("/")
    version = prefix.removeprefix("CVSS:") if prefix.startswith("CVSS:") else ""
    if version not in {"3.0", "3.1", "4.0"} or not rest:
        return None
    metrics = _metrics(rest.split("/"))
    if metrics is None:
        return None
    if version == "4.0":
        words = _decoded(metrics, _V4_REQUIRED)
        if words is None:
            return None
        return {
            "version": version,
            "vector": raw,
            "attack_vector": words["AV"],
            "attack_complexity": words["AC"],
            "attack_requirements": words["AT"],
            "privileges_required": words["PR"],
            "user_interaction": words["UI"],
            "scope": None,
            "impact": {"confidentiality": words["VC"], "integrity": words["VI"], "availability": words["VA"]},
            "subsequent_impact": {"confidentiality": words["SC"], "integrity": words["SI"], "availability": words["SA"]},
        }
    words = _decoded(metrics, _V3_REQUIRED)
    if words is None:
        return None
    return {
        "version": version,
        "vector": raw,
        "attack_vector": words["AV"],
        "attack_complexity": words["AC"],
        "attack_requirements": None,
        "privileges_required": words["PR"],
        "user_interaction": words["UI"],
        "scope": words["S"],
        "impact": {"confidentiality": words["C"], "integrity": words["I"], "availability": words["A"]},
        "subsequent_impact": None,
    }


__all__ = ["decode_cvss_vector"]
