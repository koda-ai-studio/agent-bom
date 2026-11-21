"""GCP project IAM role checks."""

from __future__ import annotations

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource
from agent_bom.iac.terraform_security_hcl import attr, tf_finding

_BROAD_GCP = frozenset({"roles/storage.admin", "roles/editor", "roles/owner"})


def tf_sec_212(res: TfResource) -> list[IaCFinding]:
    role = attr(res.block, "role")
    if role is None or role.string not in _BROAD_GCP:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-212",
            severity="high",
            title="Over-broad GCP project role",
            message=f"Project IAM resource '{res.rname}' grants {role.string} at project scope.",
            compliance=["NIST-AC-6"],
            remediation="Grant only task-specific permissions at the narrowest resource scope.",
            offset=role.offset,
        )
    ]
