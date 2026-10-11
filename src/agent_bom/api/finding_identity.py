"""Finding identity."""

from __future__ import annotations

from typing import Any


def finding_identity(finding: dict[str, Any]) -> str:
    """Stable identity used to collapse a finding across scan jobs."""
    raw_id = finding.get("id")
    if raw_id:
        return str(raw_id)
    vuln_id = finding.get("vulnerability_id") or finding.get("cve_id") or finding.get("title") or ""
    raw_asset = finding.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    package = finding.get("package") or finding.get("package_name") or asset.get("name", "")
    return f"{vuln_id}:{package}"
