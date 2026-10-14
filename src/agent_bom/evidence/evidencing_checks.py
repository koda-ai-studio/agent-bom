"""Which curated evidencing checks one finding ran, and which catalog controls they evaluate.

The catalog-backed NIST SP 800-53 line (:mod:`agent_bom.compliance_nist_catalog`)
evaluates a control only through one of ITS OWN evidencing checks. A finding's
``nist_800_53_tags`` also carry vulnerability-intrinsic tagger rules (SR-3 on
every CVE, SI-4 on high severity, ...); those are not checks, so they never
evaluate a catalog control on their own.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from agent_bom.finding import FindingType
from agent_bom.framework_mapping import _CREDENTIAL_CWES, ControlSpec

__all__ = ["finding_evaluated_controls", "finding_evidencing_checks"]


def finding_evidencing_checks(row: Mapping[str, Any]) -> set[str]:
    """Return the curated checks one serialized finding row actually ran.

    Namespaced like ``ControlSpec.evidencing_checks`` (``cwe:<CWE-ID>``). A
    finding evidences a NIST control only through one of these; the
    vulnerability-intrinsic tagger rules (SR-3 on every CVE, SI-4 on high
    severity, ...) are not checks and never evaluate a catalog control.
    """
    cwes = {str(cwe).strip().upper() for cwe in row.get("cwe_ids") or () if str(cwe).strip()}
    finding_type = row.get("finding_type")
    if str(getattr(finding_type, "value", finding_type) or "").upper() == FindingType.CREDENTIAL_EXPOSURE.value:
        cwes.update(_CREDENTIAL_CWES)
    return {f"cwe:{cwe}" for cwe in cwes}


def finding_evaluated_controls(
    row: Mapping[str, Any],
    catalog: Mapping[str, ControlSpec],
    evidenced: Collection[str],
) -> list[str]:
    """Return the curated ``nist_800_53_tags`` this finding's own checks evaluate, in tag order."""
    ran = finding_evidencing_checks(row)
    if not ran:
        return []
    evaluated: list[str] = []
    for control_id in row.get("nist_800_53_tags", []) or []:
        spec = catalog.get(control_id)
        if control_id not in evidenced or spec is None or ran.isdisjoint(spec.evidencing_checks):
            # The tag came from a vulnerability-intrinsic rule (SR-3 on every
            # CVE, SI-4 on high severity), not from a curated check this
            # finding ran. A control evidenced only by OTHER checks (CIS
            # alarms for SI-4) must not be evaluated by it.
            continue
        evaluated.append(control_id)
    return evaluated
