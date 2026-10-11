"""Finding rank."""

from __future__ import annotations

from typing import Any


def compute_effective_reach_score(payload: dict[str, Any]) -> float:
    """Return the composite effective-reach signal for a finding payload.

    Shared by the API sort path (``routes/scan.py``) and the persistence
    layer so the ``effective_reach_score`` column materialised on ingest
    matches the in-memory ranking exactly. Prefers an explicit
    ``effective_reach_score`` field, then the ``effective_reach.composite``
    breakdown, defaulting to ``0.0`` when neither is present.
    """
    from agent_bom.symbol_reach_triage import apply_composite_delta, symbol_reachability_from_payload

    reach = payload.get("effective_reach_score")
    if reach is None:
        breakdown = payload.get("effective_reach") or {}
        if isinstance(breakdown, dict):
            reach = breakdown.get("composite")
    try:
        base = float(reach or 0.0)
    except (TypeError, ValueError):
        base = 0.0
    sym = symbol_reachability_from_payload(payload)
    breakdown = payload.get("effective_reach") or {}
    if isinstance(breakdown, dict) and breakdown.get("symbol_reach_adjustment") is not None:
        return base
    return apply_composite_delta(base, sym)
