"""Expand a report schema 2.0 document back to the exact 1.0 document; references are bounded for untrusted input."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from agent_bom.output.report_refs import (
    MAX_REF_LENGTH,
    MAX_TABLE_ROWS,
    PACKING_SCHEMA_VERSION,
    PROVENANCE_REF_KEYS,
    REF_TRANSFORMS,
    REPORT_SCHEMA_V1,
    T_ASSETS,
    T_BLAST_RADIUS,
    T_CONTROLS,
    T_INVENTORY_PACKAGES,
    T_PACKAGES,
    T_PROVENANCE,
    T_ROOT_PACKAGES,
    TRANSFORMS,
    ReportExpansionLimitError,
    ReportPackingError,
    decode_fields,
    deep_copy,
    inventory_flat_packages,
    is_packed,
    package_index,
    package_occurrence_lists,
    unique_index,
)


class _Budget:
    """Running total of the bytes references add, against an optional ceiling."""

    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self.used = 0
        self._sizes: dict[int, int] = {}

    def charge(self, value: Any) -> None:
        if self.limit is None:
            return
        size = self._sizes.get(id(value))
        if size is None:
            size = len(json.dumps(value, separators=(",", ":"), default=str))
            self._sizes[id(value)] = size
        self.used += size
        if self.used > self.limit:
            raise ReportExpansionLimitError(f"report expands beyond {self.limit} bytes")


def expand_report(doc: Mapping[str, Any], *, max_expanded_bytes: int | None = None) -> dict[str, Any]:
    """Return the schema 1.0 form of a report; a 1.x document is returned as a copy.

    ``max_expanded_bytes`` bounds the bytes that references may add, so a small
    untrusted document cannot expand into an unbounded one.
    """
    try:
        return _expand(doc, max_expanded_bytes)
    except (TypeError, AttributeError, KeyError, RecursionError) as exc:
        # Shapes the reference checks did not anticipate fail closed, as malformed input.
        raise ReportPackingError(f"schema 2 report has an unexpected shape: {type(exc).__name__}") from None


def _expand(doc: Mapping[str, Any], max_expanded_bytes: int | None) -> dict[str, Any]:
    if not is_packed(doc):
        return dict(doc)
    manifest = doc.get("packing")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != PACKING_SCHEMA_VERSION:
        raise ReportPackingError("schema 2 report has no supported packing manifest")
    transforms = manifest.get("transforms")
    if not isinstance(transforms, list) or not all(isinstance(name, str) and name in TRANSFORMS for name in transforms):
        raise ReportPackingError("schema 2 report lists an unknown packing transform")
    budget = _Budget(max_expanded_bytes)
    applied = set(transforms)
    declared = manifest.get("fields", {})
    if not isinstance(declared, dict):
        raise ReportPackingError("packing.fields must map reference keys to field lists")
    fields = {ref: decode_fields(declared.get(ref), ref) for name, ref in REF_TRANSFORMS.items() if name in applied}
    provenance = _table(doc.get("provenance") if T_PROVENANCE in applied else {}, "provenance")
    expanded = _restore_provenance(doc, provenance, budget) if T_PROVENANCE in applied else deep_copy(doc)
    expanded.pop("provenance", None)
    controls = _table(expanded.pop("compliance_controls", {}) if T_CONTROLS in applied else {}, "compliance_controls")
    steps: dict[str, Callable[[dict[str, Any]], None]] = {
        T_CONTROLS: lambda report: _expand_controls(report, controls, budget),
        T_PACKAGES: lambda report: _expand_packages(report, fields["package_ref"], budget),
        T_ASSETS: lambda report: _expand_assets(report, fields["asset_ref"], budget),
        T_BLAST_RADIUS: lambda report: _expand_blast_radius(report, fields["finding_ref"], budget),
        T_INVENTORY_PACKAGES: lambda report: _expand_inventory_packages(report, budget),
        T_ROOT_PACKAGES: lambda report: _expand_root_packages(report, budget),
    }
    for name in reversed(TRANSFORMS):
        if name in applied and name in steps:
            steps[name](expanded)
    if "legacy_schema_version" not in manifest:
        # The source had no schema_version; the packer added the one this document carries.
        expanded.pop("schema_version", None)
    legacy = manifest.get("legacy_schema_version")
    version = legacy if isinstance(legacy, str) and legacy.split(".", 1)[0] == "1" else REPORT_SCHEMA_V1
    for key in ("schema_version", "spec_version"):
        if key in expanded:
            expanded[key] = version
    expanded.pop("packing", None)
    return expanded


def _table(value: object, name: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or len(value) > MAX_TABLE_ROWS:
        raise ReportPackingError(f"{name} must be an object of records")
    for key, row in value.items():
        if not isinstance(key, str) or not isinstance(row, dict):
            raise ReportPackingError(f"{name} must map IDs to objects")
    return value


def _ref(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_REF_LENGTH:
        raise ReportPackingError(f"{field} must be a non-empty ID string")
    return value


_MAX_PROVENANCE_DEPTH = 8


def _provenance_record(record_id: str, table: Mapping[str, dict[str, Any]], budget: _Budget, depth: int) -> Any:
    record = table.get(record_id)
    if record is None:
        raise ReportPackingError("a provenance reference names an unknown record")
    if depth >= _MAX_PROVENANCE_DEPTH:
        raise ReportPackingError("provenance records nest too deeply")
    budget.charge(record)
    return _restore_provenance(record, table, budget, depth + 1)


def _restore_provenance(value: Any, table: Mapping[str, dict[str, Any]], budget: _Budget, depth: int = 0) -> Any:
    """Copy containers, replacing each ``<key>_ref`` with the provenance object it names."""
    stack: list[tuple[Any, Any]] = []
    root = _shell(value)
    stack.append((value, root))
    while stack:
        source, target = stack.pop()
        if isinstance(source, dict):
            for key, child in source.items():
                original = PROVENANCE_REF_KEYS.get(key)
                if original is not None and original not in source:
                    target[original] = _provenance_record(_ref(child, key), table, budget, depth)
                    continue
                target[key] = _shell(child)
                stack.append((child, target[key]))
        elif isinstance(source, list):
            for child in source:
                target.append(_shell(child))
                stack.append((child, target[-1]))
    return root


def _shell(value: Any) -> Any:
    if isinstance(value, dict):
        return {}
    if isinstance(value, list):
        return []
    return value


def _expand_controls(doc: dict[str, Any], table: Mapping[str, dict[str, Any]], budget: _Budget) -> None:
    findings = doc.get("findings")
    if not isinstance(findings, list):
        return
    for position, finding in enumerate(findings):
        if not isinstance(finding, dict) or "control_refs" not in finding:
            continue
        refs = finding["control_refs"]
        if not isinstance(refs, list):
            raise ReportPackingError("control_refs must be a list of control IDs")
        controls = []
        for ref in refs:
            control = table.get(_ref(ref, "control_refs"))
            if control is None:
                raise ReportPackingError("control_refs names an unknown compliance control")
            budget.charge(control)
            controls.append(dict(control))
        findings[position] = {
            ("controls" if key == "control_refs" else key): (controls if key == "control_refs" else value) for key, value in finding.items()
        }


def _restore(row: dict[str, Any], source: Mapping[str, Any], keys: Mapping[str, str], ref_key: str, budget: _Budget) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for row_key, source_key in keys.items():
        if row_key not in row and source_key in source:
            budget.charge(source[source_key])
            out[row_key] = deep_copy(source[source_key])
    out.update((key, value) for key, value in row.items() if key != ref_key)
    return out


def _expand_rows(rows: object, index: Mapping[str, dict[str, Any]], keys: Mapping[str, str], ref_key: str, budget: _Budget) -> None:
    if not isinstance(rows, list):
        return
    for position, row in enumerate(rows):
        if not isinstance(row, dict) or ref_key not in row:
            continue
        source = index.get(_ref(row[ref_key], ref_key))
        if source is None:
            raise ReportPackingError(f"{ref_key} names an unknown record")
        rows[position] = _restore(row, source, keys, ref_key, budget)


def _expand_packages(doc: dict[str, Any], keys: Mapping[str, str], budget: _Budget) -> None:
    index = package_index(doc)
    for rows in package_occurrence_lists(doc):
        _expand_rows(rows, index, keys, "package_ref", budget)


def _expand_assets(doc: dict[str, Any], keys: Mapping[str, str], budget: _Budget) -> None:
    index = unique_index(doc.get("assets"), "stable_id")
    findings = doc.get("findings")
    for finding in findings if isinstance(findings, list) else []:
        asset = finding.get("asset") if isinstance(finding, dict) else None
        if isinstance(asset, dict) and "asset_ref" in asset:
            source = index.get(_ref(asset["asset_ref"], "asset_ref"))
            if source is None:
                raise ReportPackingError("asset_ref names an unknown asset")
            finding["asset"] = _restore(asset, source, keys, "asset_ref", budget)


def _expand_blast_radius(doc: dict[str, Any], keys: Mapping[str, str], budget: _Budget) -> None:
    index = unique_index(doc.get("findings"), "canonical_id")
    _expand_rows(doc.get("blast_radius"), index, keys, "finding_ref", budget)


def _expand_inventory_packages(doc: dict[str, Any], budget: _Budget) -> None:
    snapshot = doc.get("inventory_snapshot")
    if not isinstance(snapshot, dict):
        return
    flat = inventory_flat_packages(snapshot)
    if flat is None:
        raise ReportPackingError("inventory_snapshot.agents is not a list of agents with server package lists")
    for package in flat:
        budget.charge(package)
    rebuilt: dict[str, Any] = {}
    for key, value in snapshot.items():
        rebuilt[key] = value
        if key == "generated_at":
            rebuilt["packages"] = deep_copy(flat)
    rebuilt.setdefault("packages", deep_copy(flat))
    doc["inventory_snapshot"] = rebuilt


def _expand_root_packages(doc: dict[str, Any], budget: _Budget) -> None:
    entities = doc.get("ai_bom_entities")
    packages = entities.get("packages") if isinstance(entities, dict) else None
    if not isinstance(packages, list):
        raise ReportPackingError("ai_bom_entities.packages is required to restore root packages")
    budget.charge(packages)
    rebuilt: dict[str, Any] = {}
    for key, value in doc.items():
        rebuilt[key] = value
        if key == "ai_bom_entities":
            rebuilt["packages"] = deep_copy(packages)
    doc.clear()
    doc.update(rebuilt)


def load_report_document(value: Any, *, max_expanded_bytes: int | None = None) -> Any:
    """Expand a schema 2.x report to 1.0 for readers; any other value passes through unchanged."""
    return expand_report(value, max_expanded_bytes=max_expanded_bytes) if is_packed(value) else value
