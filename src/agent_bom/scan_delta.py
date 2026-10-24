"""Delta scanning — diff current scan against a baseline, report only new findings.

Usage:
    agent-bom scan --baseline-file scan-main.json --delta
    agent-bom scan --delta   # auto-loads last saved baseline from ~/.agent-bom/baseline.json

The delta key for CVEs is (vulnerability_id, ecosystem, package_name).
Package versions stay in inventory diffs, but do not reclassify an existing CVE
as new during remediation. Every other finding type (IaC, secrets, skills,
posture) is keyed by type, asset location, title and description with line
references removed. Exit code is based on *new* findings only; pre-existing
findings are suppressed.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Optional

from agent_bom.package_utils import vulnerability_occurrence_key
from agent_bom.storage import state_home

_logger = logging.getLogger(__name__)


def default_baseline_path() -> Path:
    """Default path for auto-saved baselines, under the active state dir."""
    return state_home.state_path("baseline.json")


# ---------------------------------------------------------------------------
# Finding key type
# ---------------------------------------------------------------------------

# A delta key identifies a vulnerability occurrence across package upgrades.
DeltaKey = tuple[str, str, str]


def _make_key(vuln_id: str, package: str, ecosystem: str = "") -> DeltaKey:
    """Build a version-stable delta key from a blast-radius JSON item."""
    return vulnerability_occurrence_key(vuln_id, package, ecosystem)


def extract_delta_keys(scan_json: dict) -> set[DeltaKey]:
    """Extract the set of finding keys from a serialized scan output dict."""
    keys: set[DeltaKey] = set()
    for item in scan_json.get("blast_radius", []):
        vuln_id = item.get("vulnerability_id", "")
        package = item.get("package", "")
        if vuln_id and package:
            keys.add(_make_key(vuln_id, package, item.get("ecosystem", "")))
    return keys


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------


def load_baseline(path: str | Path) -> dict:
    """Load a baseline scan JSON from disk.

    Returns the parsed dict, or raises ``FileNotFoundError`` / ``ValueError``
    if the file is missing or not valid scan output.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Baseline file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline file is not valid JSON: {p}") from exc
    if "blast_radius" not in data:
        raise ValueError(f"Baseline file does not look like an agent-bom scan output (missing 'blast_radius' key): {p}")
    return data


def save_baseline(scan_json: dict, path: str | Path | None = None) -> Path:
    """Persist a scan result as the new baseline.

    Writes to ``path`` (or ``~/.agent-bom/baseline.json`` by default).
    Returns the path written.
    """
    p = Path(path) if path else default_baseline_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(scan_json, indent=2), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Core diff logic
# ---------------------------------------------------------------------------


class DeltaResult:
    """Result of comparing current scan findings against a baseline."""

    def __init__(
        self,
        new_items: list[dict],
        pre_existing_items: list[dict],
        baseline_path: Optional[str],
    ) -> None:
        self.new_items = new_items  # findings not in baseline
        self.pre_existing_items = pre_existing_items  # findings that were already in baseline
        self.baseline_path = baseline_path

    @property
    def new_count(self) -> int:
        return len(self.new_items)

    @property
    def pre_existing_count(self) -> int:
        return len(self.pre_existing_items)

    @property
    def has_new(self) -> bool:
        return bool(self.new_items)

    def summary_line(self) -> str:
        parts = []
        if self.new_count:
            parts.append(f"{self.new_count} new")
        if self.pre_existing_count:
            parts.append(f"{self.pre_existing_count} pre-existing (suppressed)")
        if not parts:
            return "No findings (delta clean)"
        return ", ".join(parts)


def compute_delta(
    current_scan: dict,
    baseline: dict,
) -> DeltaResult:
    """Diff current scan against baseline; return new and pre-existing items.

    Args:
        current_scan: serialized scan JSON (output of ``to_json(report)``).
        baseline: previously saved scan JSON to compare against.

    Returns:
        :class:`DeltaResult` with ``new_items`` (not in baseline) and
        ``pre_existing_items`` (already in baseline).
    """
    baseline_counts: Counter[DeltaKey] = Counter()
    for item in baseline.get("blast_radius", []):
        vuln_id = item.get("vulnerability_id", "")
        package = item.get("package", "")
        if vuln_id and package:
            baseline_counts[_make_key(vuln_id, package, item.get("ecosystem", ""))] += 1
    _logger.debug("Baseline has %d findings", sum(baseline_counts.values()))

    new_items: list[dict] = []
    pre_existing_items: list[dict] = []

    for item in current_scan.get("blast_radius", []):
        vuln_id = item.get("vulnerability_id", "")
        package = item.get("package", "")
        if not vuln_id or not package:
            _logger.debug("Skipping malformed blast_radius item: %s", item)
            continue
        key = _make_key(vuln_id, package, item.get("ecosystem", ""))
        legacy_key: DeltaKey = (key[0], "", key[2])
        matched_key = key if baseline_counts[key] else legacy_key
        if baseline_counts[matched_key]:
            baseline_counts[matched_key] -= 1
            pre_existing_items.append(item)
        else:
            new_items.append(item)

    _logger.info(
        "Delta: %d new, %d pre-existing (baseline had %d)",
        len(new_items),
        len(pre_existing_items),
        sum(baseline_counts.values()) + len(pre_existing_items),
    )
    return DeltaResult(
        new_items=new_items,
        pre_existing_items=pre_existing_items,
        baseline_path=None,
    )


def apply_delta_to_scan(
    scan_json: dict,
    delta: DeltaResult,
) -> dict:
    """Return a modified scan dict containing only new findings.

    The ``summary`` counters are also recomputed to reflect delta-only counts.
    The original scan dict is NOT mutated; a shallow copy with replaced
    ``blast_radius`` and updated ``summary`` is returned.
    """
    result = dict(scan_json)
    result["blast_radius"] = delta.new_items
    result["delta"] = {
        "enabled": True,
        "new_count": delta.new_count,
        "pre_existing_count": delta.pre_existing_count,
        "baseline_path": delta.baseline_path,
    }
    # Recompute summary counts
    if "summary" in result and isinstance(result["summary"], dict):
        summary = dict(result["summary"])
        summary["total_vulnerabilities"] = delta.new_count
        summary["delta_note"] = delta.summary_line()
        result["summary"] = summary
    return result


# ---------------------------------------------------------------------------
# Non-CVE findings (IaC, secrets, skills, posture, ...)
# ---------------------------------------------------------------------------

# A non-CVE delta key is (finding_type, asset location, title, description)
# with line references removed, so an unrelated edit that shifts a finding
# down the file does not reclassify it as new.
FindingDeltaKey = tuple[str, str, str, str]

_LINE_REFERENCE = re.compile(r":\d+(?::\d+)?\b|\blines?\s+\d+(?:\s*[-–]\s*\d+)?", re.IGNORECASE)


def _without_line_refs(text: str) -> str:
    return " ".join(_LINE_REFERENCE.sub("", text).split())


def finding_delta_key(finding: Mapping[str, Any]) -> FindingDeltaKey | None:
    """Return the line-independent delta key of a serialized unified finding.

    CVE findings return ``None``: they are matched by the package-occurrence
    key above, which survives package upgrades.
    """
    finding_type = str(finding.get("finding_type") or "")
    if not finding_type or finding_type == "CVE":
        return None
    raw_asset = finding.get("asset")
    asset: Mapping[str, Any] = raw_asset if isinstance(raw_asset, Mapping) else {}
    location = str(asset.get("location") or asset.get("identifier") or asset.get("name") or "")
    return (
        finding_type,
        location,
        _without_line_refs(str(finding.get("title") or "")),
        _without_line_refs(str(finding.get("description") or "")),
    )


class FindingDelta:
    """Current non-CVE finding ids split into new and pre-existing."""

    def __init__(self, new_ids: set[str], pre_existing_ids: set[str]) -> None:
        self.new_ids = new_ids
        self.pre_existing_ids = pre_existing_ids


def compute_finding_delta(current_findings: list[dict], baseline: dict) -> FindingDelta:
    """Split current non-CVE findings into new and pre-existing by delta key.

    Matching is a multiset: two identical occurrences against one baseline
    occurrence leave one of them new. A baseline without a unified
    ``findings`` list (older reports) suppresses nothing, so the gate fails
    closed rather than hiding findings it cannot prove were already present.
    """
    baseline_counts: Counter[FindingDeltaKey] = Counter()
    for item in baseline.get("findings") or []:
        if isinstance(item, Mapping):
            key = finding_delta_key(item)
            if key is not None:
                baseline_counts[key] += 1

    new_ids: set[str] = set()
    pre_existing_ids: set[str] = set()
    for item in current_findings:
        key = finding_delta_key(item)
        finding_id = str(item.get("id") or "")
        if key is None or not finding_id:
            continue
        if baseline_counts[key]:
            baseline_counts[key] -= 1
            pre_existing_ids.add(finding_id)
        else:
            new_ids.add(finding_id)
    return FindingDelta(new_ids=new_ids, pre_existing_ids=pre_existing_ids)


def _count_by(items: list[Any], field: str) -> dict[str, int]:
    counts: Counter[str] = Counter(str(item.get(field)) for item in items if isinstance(item, dict))
    return dict(counts)


def _secret_counts(kept: list[Any]) -> dict[str, Any]:
    return {
        "findings": kept,
        "total": len(kept),
        "critical": sum(1 for item in kept if isinstance(item, dict) and item.get("severity") == "critical"),
        "by_type": _count_by(kept, "secret_type"),
        "by_category": _count_by(kept, "category"),
    }


def prune_pre_existing_findings(report: Any, pre_existing_ids: set[str]) -> int:
    """Drop pre-existing non-CVE findings from every report block that emits them.

    Unified findings are projected from several side blocks, so each source is
    pruned in place; every renderer and exit gate then reads the same
    new-only set. Returns how many pre-existing ids are still emitted by a
    block that cannot be pruned here (logged, never hidden).
    """
    if not pre_existing_ids:
        return 0
    from agent_bom.finding import iac_finding_to_finding, secret_dict_to_finding

    report.findings = [finding for finding in report.findings if str(finding.id) not in pre_existing_ids]

    iac_data = report.iac_findings_data
    if isinstance(iac_data, dict) and isinstance(iac_data.get("findings"), list):
        kept = [
            item
            for item in iac_data["findings"]
            if not isinstance(item, dict) or str(iac_finding_to_finding(item).id) not in pre_existing_ids
        ]
        report.iac_findings_data = {**iac_data, "findings": kept, "total": len(kept)}

    inventory = report.ai_inventory_data
    secrets = inventory.get("secrets") if isinstance(inventory, dict) else None
    if isinstance(secrets, dict) and isinstance(secrets.get("findings"), list):
        kept_secrets = [
            item
            for item in secrets["findings"]
            if not isinstance(item, dict) or str(secret_dict_to_finding(item).id) not in pre_existing_ids
        ]
        report.ai_inventory_data = {**inventory, "secrets": {**secrets, **_secret_counts(kept_secrets)}}

    remaining = {str(finding.id) for finding in report.to_findings()} & pre_existing_ids
    if remaining:
        _logger.warning("Delta: %d pre-existing finding(s) come from a report block that cannot be pruned; still reported", len(remaining))
    return len(remaining)
