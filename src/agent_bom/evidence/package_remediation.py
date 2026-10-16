"""Compare local installed metadata against one pinned OSV advisory.

No imports from the inspected installation, network calls or package changes.
Content digests bind receipts but do not authenticate the host or collector.
"""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from agent_bom import __version__
from agent_bom.core.versions.osv import range_match_state, range_windows

MAX_BYTES = 2_000_000
MAX_ENTRIES = 20_000


class _CollectionBudgetError(ValueError):
    """A bounded collector must retain uncertainty when its budget is exhausted."""


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: str
    metadata_path: str
    metadata: str = Field(max_length=MAX_BYTES)
    metadata_digest: str


class PackageCapture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["package-remediation-capture.v1"]
    receipt_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    scope_id: str
    installation_directory: str
    package: str
    captured_at: AwareDatetime
    collector_version: str
    collection_status: Literal["complete", "unavailable"]
    reason_codes: list[str]
    observations: list[Observation] = Field(max_length=MAX_ENTRIES)
    advisory: dict[str, Any]
    advisory_digest: str


def _metadata(text: str) -> tuple[str, str]:
    message = Parser().parsestr(text)
    names, versions = message.get_all("Name", []), message.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1 or not names[0].strip():
        raise ValueError("ambiguous distribution metadata")
    name = canonicalize_name(names[0], validate=True)
    Version(versions[0])
    return name, versions[0]


def _read_distribution(entry: Path) -> tuple[Path, str, str, str, int]:
    if entry.is_symlink() or entry.name.endswith(".egg-info"):
        raise ValueError("unsupported metadata layout")
    path = entry / "METADATA"
    if path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise ValueError("unsupported metadata file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("metadata exceeds collection budget")
    text = raw.decode("utf-8")
    name, version = _metadata(text)
    with path.open("rb") as stream:
        if stream.read(MAX_BYTES + 1) != raw:
            raise ValueError("metadata changed during collection")
    return path, text, name, version, len(raw)


def _entries(root: Path) -> list[Path]:
    result: list[Path] = []
    for entry in root.iterdir():
        if len(result) >= MAX_ENTRIES:
            raise _CollectionBudgetError("installation exceeds collection budget")
        result.append(entry)
    return sorted(result)


def _collect_metadata(initial: list[Path], package: str) -> tuple[list[dict[str, str]], set[str]]:
    observations: list[dict[str, str]] = []
    reasons: set[str] = set()
    total_bytes = 0
    for entry in initial:
        if not entry.name.endswith((".dist-info", ".egg-info")):
            continue
        try:
            path, text, name, version, size = _read_distribution(entry)
            total_bytes += size
            if total_bytes > 16 * MAX_BYTES:
                reasons.add("collection_budget_exhausted")
                break
            if name == package:
                observations.append({"version": version, "metadata_path": str(path), "metadata": text, "metadata_digest": digest(text)})
        except (OSError, ValueError, UnicodeError):
            reasons.add("metadata_unavailable_or_unsupported")
    return observations, reasons


def capture_package(
    directory: Path, *, package: str, tenant_id: str, advisory: dict[str, Any], now: datetime | None = None
) -> dict[str, Any]:
    """Read one explicit installation directory, retaining exact metadata bytes."""
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() is None or not tenant_id.strip():
        raise ValueError("timezone and tenant scope are required")
    package = canonicalize_name(package, validate=True)
    root = directory.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("installation scope must be a directory")
    if len(json.dumps(advisory)) > MAX_BYTES:
        raise ValueError("advisory exceeds receipt budget")
    stat = root.stat()
    scope = digest([platform.node(), str(root), stat.st_dev, stat.st_ino])
    try:
        initial = _entries(root)
        observations, reasons = _collect_metadata(initial, package)
        if initial != _entries(root):
            reasons.add("installation_changed_during_collection")
    except _CollectionBudgetError:
        observations, reasons = [], {"collection_budget_exhausted"}
    final_stat = root.stat()
    if (stat.st_dev, stat.st_ino) != (final_stat.st_dev, final_stat.st_ino):
        reasons.add("installation_changed_during_collection")
    if len(observations) != 1:
        reasons.add("package_missing_or_ambiguous")
    # Recheck selected metadata after enumeration to catch an overlapping upgrade.
    for observation in observations:
        try:
            _, text, _, _, _ = _read_distribution(Path(observation["metadata_path"]).parent)
            if digest(text) != observation["metadata_digest"]:
                reasons.add("installation_changed_during_collection")
        except (OSError, ValueError, UnicodeError):
            reasons.add("installation_changed_during_collection")
    capture = PackageCapture(
        schema_version="package-remediation-capture.v1",
        receipt_id=str(uuid4()),
        tenant_id=tenant_id.strip(),
        scope_id=scope,
        installation_directory=str(root),
        package=package,
        captured_at=now,
        collector_version=__version__,
        collection_status="unavailable" if reasons else "complete",
        reason_codes=sorted(reasons),
        observations=[Observation.model_validate(value) for value in observations],
        advisory=advisory,
        advisory_digest=digest(advisory),
    ).model_dump(mode="json")
    return {**capture, "digest": digest(capture)}


def _range_states(window: dict[str, Any], version: str) -> list[str]:
    if window.get("type") != "ECOSYSTEM" or not window.get("events"):
        return ["unknown"]
    events = window["events"]
    if any(
        not isinstance(event, dict)
        or len(event) != 1
        or next(iter(event)) not in {"introduced", "fixed", "last_affected"}
        or not isinstance(next(iter(event.values())), str)
        for event in events
    ):
        return ["unknown"]
    for event in events:
        Version(next(iter(event.values())))
    return [range_match_state(version, introduced, fixed, last, "pypi") for introduced, fixed, last in range_windows(events, "pypi")]


def _row_states(row: dict[str, Any], version: str) -> list[str]:
    listed, ranges = row.get("versions", []), row.get("ranges")
    if not isinstance(listed, list) or not isinstance(ranges, list) or not ranges:
        return ["unknown"]
    states = ["affected" for item in listed if Version(item) == Version(version)]
    for window in ranges:
        states.extend(_range_states(window, version))
    return states


def _advisory_state(advisory: dict[str, Any], package: str, version: str) -> str:
    """Use canonical OSV windows, with strict bounds before declaring a fix."""
    if not advisory.get("id") or advisory.get("withdrawn") or not isinstance(advisory.get("affected"), list):
        return "unknown"
    if any(not isinstance(row, dict) or not isinstance(row.get("package"), dict) for row in advisory["affected"]):
        return "unknown"
    selected = [
        row
        for row in advisory["affected"]
        if row["package"].get("ecosystem") == "PyPI" and canonicalize_name(str(row["package"].get("name", ""))) == package
    ]
    try:
        states = [state for row in selected for state in _row_states(row, version)]
    except (ValueError, TypeError, AttributeError, KeyError, InvalidVersion):
        return "unknown"
    if "affected" in states:
        return "affected"
    return "unaffected" if states and all(state == "unaffected" for state in states) else "unknown"


def _validated(raw: dict[str, Any]) -> PackageCapture:
    body = {key: value for key, value in raw.items() if key != "digest"}
    if digest(body) != raw.get("digest"):
        raise ValueError("receipt digest mismatch")
    record = PackageCapture.model_validate(body)
    if digest(record.advisory) != record.advisory_digest:
        raise ValueError("advisory digest mismatch")
    for observation in record.observations:
        if digest(observation.metadata) != observation.metadata_digest or _metadata(observation.metadata) != (
            record.package,
            observation.version,
        ):
            raise ValueError("metadata receipt mismatch")
    return record


def _crossed_fixes(advisory: dict[str, Any], package: str, before: str, after: str) -> list[str]:
    fixes = set()
    for row in advisory["affected"]:
        coordinates = row.get("package", {})
        if coordinates.get("ecosystem") != "PyPI" or canonicalize_name(coordinates.get("name", "")) != package:
            continue
        for interval in row.get("ranges", []):
            for introduced, fixed, last in range_windows(interval["events"], "pypi"):
                if fixed and range_match_state(before, introduced, fixed, last, "pypi") == "affected" and Version(after) >= Version(fixed):
                    fixes.add(fixed)
    return sorted(fixes)


def compare_packages(
    before: dict[str, Any], after: dict[str, Any], *, now: datetime | None = None, max_age_seconds: int = 3600
) -> dict[str, Any]:
    """Verify one installed-version change; no campaign or deployment is closed."""
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() is None or not 1 <= max_age_seconds <= 86400:
        raise ValueError("timezone and a bounded freshness policy are required")
    result: dict[str, Any] = {
        "schema_version": "package-remediation-verification.v1",
        "outcome": "unavailable_evidence",
        "claim_scope": "installed_distribution_metadata",
        "independently_verified": False,
        "runtime_loaded_version_verified": False,
        "before_digest": before.get("digest"),
        "after_digest": after.get("digest"),
        "compared_at": now.isoformat(),
        "max_age_seconds": max_age_seconds,
        "reason_codes": [],
        "fixed_versions": [],
        "limits": [
            "One directory and pinned advisory; other installations and advisories are outside scope.",
            "Metadata does not prove package file integrity, running-process state or exploitability.",
            "Local receipts and tenant labels are not authenticated collector or authorization evidence.",
        ],
    }

    def unavailable(reason: str) -> dict[str, Any]:
        return {**result, "reason_codes": [reason]}

    try:
        old, new = _validated(before), _validated(after)
    except (ValueError, TypeError, ValidationError):
        return unavailable("receipt_invalid")
    if any(
        getattr(old, field) != getattr(new, field)
        for field in ("tenant_id", "scope_id", "installation_directory", "package", "advisory_digest")
    ):
        return unavailable("scope_or_advisory_changed")
    if old.receipt_id == new.receipt_id or not old.captured_at < new.captured_at <= now:
        return unavailable("capture_chronology_invalid")
    if (now - new.captured_at).total_seconds() > max_age_seconds:
        return unavailable("candidate_stale")
    if any(item.collection_status != "complete" or item.reason_codes or len(item.observations) != 1 for item in (old, new)):
        return unavailable("collection_incomplete")
    old_version, new_version = old.observations[0].version, new.observations[0].version
    result.update(
        tenant_id=new.tenant_id,
        scope_id=new.scope_id,
        package=new.package,
        advisory_id=new.advisory.get("id"),
        advisory_digest=new.advisory_digest,
        baseline_version=old_version,
        candidate_version=new_version,
        before_receipt_id=old.receipt_id,
        after_receipt_id=new.receipt_id,
    )
    old_state = _advisory_state(old.advisory, old.package, old_version)
    new_state = _advisory_state(new.advisory, new.package, new_version)
    if old_state != "affected":
        return unavailable("affected_baseline_not_established")
    if new_state == "affected":
        return {**result, "outcome": "still_affected"}
    if new_state != "unaffected" or Version(new_version) <= Version(old_version):
        return unavailable("fixed_version_not_established")
    fixes = _crossed_fixes(new.advisory, new.package, old_version, new_version)
    if not fixes:
        return unavailable("fixed_version_not_established")
    return {**result, "outcome": "verified_for_selected_advisory", "fixed_versions": fixes}
