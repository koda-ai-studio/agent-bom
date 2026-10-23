"""Fleet-wide statistics shared by ``/v1/fleet/stats``."""

from __future__ import annotations

from typing import Any

from agent_bom.fleet.trust_scoring import LOW_TRUST_THRESHOLD


def fleet_stats_payload(agents: list[Any]) -> dict[str, Any]:
    """``/v1/fleet/stats`` body; low trust uses the shared 0-100 threshold."""
    by_state: dict[str, int] = {}
    by_env: dict[str, int] = {}
    trust_scores: list[float] = []
    for a in agents:
        state_value = getattr(a.lifecycle_state, "value", str(a.lifecycle_state))
        by_state[state_value] = by_state.get(state_value, 0) + 1
        env = a.environment or "unset"
        by_env[env] = by_env.get(env, 0) + 1
        trust_scores.append(float(getattr(a, "trust_score", 0.0) or 0.0))
    return {
        "total": len(agents),
        "by_state": by_state,
        "by_environment": by_env,
        "avg_trust_score": round(sum(trust_scores) / len(trust_scores), 1) if trust_scores else 0.0,
        "low_trust_count": sum(1 for s in trust_scores if s < LOW_TRUST_THRESHOLD),
    }
