"""Control tags for graph toxic-combination findings, keyed by rule id."""

from __future__ import annotations

# Graph toxic combinations, keyed by rule id. A public foothold on a known
# vulnerability is evidence against flaw remediation and boundary protection;
# reach into sensitive data or lateral roles is evidence against access
# enforcement / least privilege. OWASP LLM Top 10 applies only where an AI
# agent is part of the combination (excessive agency); web OWASP Top 10 IDs
# have no catalog here and are deliberately not emitted.
_PUBLIC_VULNERABLE_TAGS: dict[str, tuple[str, ...]] = {
    "nist_800_53_tags": ("SI-2",),
    "soc2_tags": ("CC6.6",),
}
TOXIC_COMBINATION_CONTROLS: dict[str, dict[str, tuple[str, ...]]] = {
    "PUBLIC_EXPOSED_KEV": _PUBLIC_VULNERABLE_TAGS,
    "PUBLIC_EXPOSED_RCE": _PUBLIC_VULNERABLE_TAGS,
    "PUBLIC_EXPOSED_NETWORK_EXPLOITABLE": _PUBLIC_VULNERABLE_TAGS,
    "PUBLIC_EXPOSED_VULNERABLE": _PUBLIC_VULNERABLE_TAGS,
    "PUBLIC_TO_SENSITIVE_DATA": {"nist_800_53_tags": ("AC-3",), "soc2_tags": ("CC6.6",)},
    "OVERPERMISSIONED_TO_SENSITIVE": {"nist_800_53_tags": ("AC-6",), "soc2_tags": ("CC6.1",)},
    "AGENT_REACHES_PRIVILEGED": {
        "owasp_tags": ("LLM06",),
        "owasp_agentic_tags": ("ASI03",),
        "nist_800_53_tags": ("AC-6", "IA-5"),
    },
    "PUBLIC_PERMISSION_LATERAL": {"nist_800_53_tags": ("AC-6",), "soc2_tags": ("CC6.6",)},
}

__all__ = ["TOXIC_COMBINATION_CONTROLS"]
