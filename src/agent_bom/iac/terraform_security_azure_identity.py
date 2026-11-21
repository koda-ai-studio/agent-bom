"""Azure broad-role assignment checks."""

from __future__ import annotations

import re

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource
from agent_bom.iac.terraform_security_hcl import attr, tf_finding

_AZURE_SCOPE = re.compile(r"(?:data\.)?azurerm_(?:resource_group|subscription)\.[\w-]+\.id$")
_AZURE_LITERAL_SCOPE = re.compile(r"/subscriptions/[^/]+(?:/resourceGroups/[^/]+)?/?$", re.IGNORECASE)


def tf_sec_113(res: TfResource) -> list[IaCFinding]:
    role, scope = attr(res.block, "role_definition_name"), attr(res.block, "scope")
    if role is None or role.string not in {"Owner", "Contributor"} or scope is None:
        return []
    if not (_AZURE_SCOPE.fullmatch(scope.raw) or _AZURE_LITERAL_SCOPE.fullmatch(scope.string or "")):
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-113",
            severity="high",
            title="Broad Azure role at resource-group or subscription scope",
            message=f"Role assignment '{res.rname}' grants {role.string} across a resource group or subscription.",
            compliance=["NIST-AC-6"],
            remediation="Use a task-specific role at the narrowest resource scope.",
            offset=role.offset,
        )
    ]
