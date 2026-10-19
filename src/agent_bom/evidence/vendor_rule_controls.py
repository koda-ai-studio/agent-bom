"""Control tags for vendor best-practice failures, keyed by exact rule id.

Vendor best practices are not official framework controls, and there is no
authoritative crosswalk, so a rule is listed only when its failure directly
evidences one control objective. Unlisted rules stay unmapped on purpose:

* Supabase advisors that are hygiene or availability concerns (mutable search
  path, outdated extensions, foreign-key shape) do not evidence access control.
* No web OWASP Top 10 catalog ships here, so OWASP IDs are not emitted.
"""

from __future__ import annotations

from agent_bom.evidence.toxic_combination_controls import TOXIC_COMBINATION_CONTROLS

# Data reachable through the project API without row-level access enforcement.
_UNENFORCED_DATA_ACCESS: dict[str, tuple[str, ...]] = {
    "nist_800_53_tags": ("AC-3",),
    "soc2_tags": ("CC6.1",),
}

VENDOR_RULE_CONTROLS: dict[str, dict[str, tuple[str, ...]]] = {
    # Deployments built from untrusted fork changes without approval: change
    # authorization. NIST CM-3 is the matching objective but is not in the
    # scoring catalog, so it is not emitted.
    "vercel.git_fork_protection": {"soc2_tags": ("CC8.1",)},
    # Supabase Security Advisor lints (names as returned by the Management API).
    "rls_disabled_in_public": _UNENFORCED_DATA_ACCESS,
    "policy_exists_rls_disabled": _UNENFORCED_DATA_ACCESS,
    "sensitive_columns_exposed": _UNENFORCED_DATA_ACCESS,
    "auth_users_exposed": _UNENFORCED_DATA_ACCESS,
}

# Finding type value -> rule id -> control tags, for every rule-keyed shape.
RULE_KEYED_CONTROLS: dict[str, dict[str, dict[str, tuple[str, ...]]]] = {
    "COMBINATION": TOXIC_COMBINATION_CONTROLS,
    "CLOUD_BEST_PRACTICE_FAIL": VENDOR_RULE_CONTROLS,
}

__all__ = ["RULE_KEYED_CONTROLS", "VENDOR_RULE_CONTROLS"]
