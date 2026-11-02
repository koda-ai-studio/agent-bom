"""Compatibility path for the finding SLA policy, which lives in ``agent_bom.core.sla``."""

from agent_bom.core.sla import SEVERITY_SLA_DAYS as SEVERITY_SLA_DAYS
from agent_bom.core.sla import SLA_DUE_SOURCES as SLA_DUE_SOURCES
from agent_bom.core.sla import SLA_POLICY_SOURCE as SLA_POLICY_SOURCE
from agent_bom.core.sla import carry_finding_sla as carry_finding_sla
from agent_bom.core.sla import finding_owner as finding_owner
from agent_bom.core.sla import finding_sla_fields as finding_sla_fields
from agent_bom.core.sla import merge_finding_sla as merge_finding_sla
from agent_bom.core.sla import sla_due_at as sla_due_at

__all__ = [
    "SEVERITY_SLA_DAYS",
    "SLA_DUE_SOURCES",
    "SLA_POLICY_SOURCE",
    "carry_finding_sla",
    "finding_owner",
    "finding_sla_fields",
    "merge_finding_sla",
    "sla_due_at",
]
