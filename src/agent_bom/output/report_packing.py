"""Scan report schema 2.0: each shared record is written once and referenced by ID.

Schema 1.0 repeats the same records in several sections: every finding carries
its compliance controls inline, each blast-radius row repeats its finding, each
package occurrence repeats its entity row, each finding repeats its asset row,
and the same provenance objects appear wherever a package is mentioned.
:func:`pack_report` writes each of those records once and replaces the copies
with references; :func:`expand_report` restores the 1.0 document exactly.

A value is replaced by a reference only when the referenced record holds the
same value, so a record that differs at one occurrence keeps that value inline.
``packing.transforms`` lists the rewrites a document carries; readers apply
exactly those and reject any they do not know.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.output.report_expansion import expand_report, load_report_document
from agent_bom.output.report_refs import (
    ASSET_KEYS,
    BLAST_RADIUS_KEYS,
    PACKAGE_KEYS,
    PACKING_SCHEMA_VERSION,
    PROVENANCE_KEYS,
    PROVENANCE_REF_KEYS,
    REPORT_SCHEMA_V1,
    REPORT_SCHEMA_V2,
    REPORT_SCHEMA_VERSIONS,
    T_ASSETS,
    T_BLAST_RADIUS,
    T_CONTROLS,
    T_INVENTORY_PACKAGES,
    T_PACKAGES,
    T_PROVENANCE,
    T_ROOT_PACKAGES,
    TRANSFORMS,
    UNTRUSTED_MAX_EXPANDED_BYTES,
    ReportExpansionLimitError,
    ReportPackingError,
    deep_copy,
    inventory_flat_packages,
    is_packed,
    package_index,
    package_occurrence_lists,
    unique_index,
)

__all__ = [
    "PACKING_SCHEMA_VERSION",
    "PROVENANCE_KEYS",
    "REPORT_SCHEMA_V1",
    "REPORT_SCHEMA_V2",
    "REPORT_SCHEMA_VERSIONS",
    "TRANSFORMS",
    "UNTRUSTED_MAX_EXPANDED_BYTES",
    "ReportExpansionLimitError",
    "ReportPackingError",
    "expand_report",
    "is_packed",
    "load_report_document",
    "pack_report",
]


def pack_report(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Return the schema 2.0 form of a 1.0 report; the input is not modified.

    A document that is already 2.x is returned unchanged.
    """
    if is_packed(doc):
        return dict(doc)
    provenance: dict[str, dict[str, Any]] = {}
    # A key already named like a reference would be read back as one; leave such documents' provenance inline.
    packed = deep_copy(doc) if _contains_key(doc, PROVENANCE_REF_KEYS) else _intern_provenance(doc, provenance)
    applied: list[str] = []
    if provenance:
        applied.append(T_PROVENANCE)
    for name, step in (
        (T_ROOT_PACKAGES, _pack_root_packages),
        (T_INVENTORY_PACKAGES, _pack_inventory_packages),
        (T_BLAST_RADIUS, _pack_blast_radius),
        (T_ASSETS, _pack_assets),
        (T_PACKAGES, _pack_packages),
        (T_CONTROLS, _pack_controls),
    ):
        if step(packed):
            applied.append(name)
    result: dict[str, Any] = {}
    for key, value in packed.items():
        if key in ("schema_version", "spec_version"):
            value = REPORT_SCHEMA_V2
        result[key] = value
    result.setdefault("schema_version", REPORT_SCHEMA_V2)
    if provenance:
        result["provenance"] = provenance
    result["packing"] = {"schema_version": PACKING_SCHEMA_VERSION, "legacy_schema_version": _legacy_version(doc), "transforms": applied}
    return result


def _legacy_version(doc: Mapping[str, Any]) -> str:
    version = doc.get("schema_version")
    return version if isinstance(version, str) else REPORT_SCHEMA_V1


def _record_id(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _contains_key(value: Any, keys: Mapping[str, str]) -> bool:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if any(key in keys for key in item):
                return True
            stack.extend(child for child in item.values() if isinstance(child, (dict, list)))
        elif isinstance(item, list):
            stack.extend(child for child in item if isinstance(child, (dict, list)))
    return False


def _intern_provenance(value: Any, table: dict[str, dict[str, Any]]) -> Any:
    """Copy containers, replacing each non-empty provenance object with a ``<key>_ref`` ID."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            ref_key = f"{key}_ref"
            if key in PROVENANCE_KEYS and isinstance(child, dict) and child and ref_key not in value:
                record_id = f"prov:{_record_id(child)}"
                if record_id not in table:
                    table[record_id] = _intern_provenance(child, table)
                out[ref_key] = record_id
            else:
                out[key] = _intern_provenance(child, table)
        return out
    if isinstance(value, list):
        return [_intern_provenance(child, table) for child in value]
    return value


def _pack_root_packages(doc: dict[str, Any]) -> bool:
    entities = doc.get("ai_bom_entities")
    if "packages" in doc and isinstance(entities, dict) and doc["packages"] == entities.get("packages"):
        del doc["packages"]
        return True
    return False


def _pack_inventory_packages(doc: dict[str, Any]) -> bool:
    snapshot = doc.get("inventory_snapshot")
    if isinstance(snapshot, dict) and "packages" in snapshot and snapshot["packages"] == inventory_flat_packages(snapshot):
        del snapshot["packages"]
        return True
    return False


def _inherit(row: dict[str, Any], source: Mapping[str, Any], keys: Mapping[str, str], ref_key: str, ref: str) -> dict[str, Any] | None:
    """Drop the values ``row`` shares with ``source``; None when the result could not be expanded exactly."""
    if ref_key in row:
        return None
    for row_key, source_key in keys.items():
        if row_key not in row and source_key in source:
            return None
    out: dict[str, Any] = {ref_key: ref}
    for key, value in row.items():
        shared_key = keys.get(key)
        if shared_key is not None and shared_key in source and source[shared_key] == value:
            continue
        out[key] = value
    return out


def _pack_rows(rows: object, index: Mapping[str, dict[str, Any]], id_key: str, keys: Mapping[str, str], ref_key: str) -> bool:
    if not isinstance(rows, list):
        return False
    changed = False
    for position, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get(id_key), str):
            continue
        source = index.get(row[id_key])
        packed = _inherit(row, source, keys, ref_key, row[id_key]) if source is not None else None
        if packed is not None:
            rows[position] = packed
            changed = True
    return changed


def _has_ref_key(rows: Iterable[object], ref_key: str) -> bool:
    return any(isinstance(row, dict) and ref_key in row for row in rows)


def _pack_blast_radius(doc: dict[str, Any]) -> bool:
    rows = doc.get("blast_radius")
    if not isinstance(rows, list) or _has_ref_key(rows, "finding_ref"):
        return False
    index = unique_index(doc.get("findings"), "canonical_id")
    return _pack_rows(rows, index, "canonical_id", BLAST_RADIUS_KEYS, "finding_ref")


def _finding_assets(doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings = doc.get("findings")
    rows = findings if isinstance(findings, list) else []
    return [row for row in rows if isinstance(row, dict) and isinstance(row.get("asset"), dict)]


def _pack_assets(doc: dict[str, Any]) -> bool:
    findings = _finding_assets(doc)
    if _has_ref_key((finding["asset"] for finding in findings), "asset_ref"):
        return False
    index = unique_index(doc.get("assets"), "stable_id")
    changed = False
    for finding in findings:
        asset = finding["asset"]
        if isinstance(asset, dict) and isinstance(asset.get("stable_id"), str) and asset["stable_id"] in index:
            packed = _inherit(asset, index[asset["stable_id"]], ASSET_KEYS, "asset_ref", asset["stable_id"])
            if packed is not None:
                finding["asset"] = packed
                changed = True
    return changed


def _pack_packages(doc: dict[str, Any]) -> bool:
    occurrence_lists = list(package_occurrence_lists(doc))
    if any(_has_ref_key(rows, "package_ref") for rows in occurrence_lists):
        return False
    index = package_index(doc)
    changed = False
    for rows in occurrence_lists:
        changed = _pack_rows(rows, index, "stable_id", PACKAGE_KEYS, "package_ref") or changed
    return changed


def _control_id(control: Mapping[str, Any]) -> str:
    framework = str(control.get("framework") or "control")
    name = str(control.get("control") or control.get("id") or "")
    return f"{framework}:{name}:{_record_id(control)[:8]}"


def _pack_controls(doc: dict[str, Any]) -> bool:
    findings = doc.get("findings")
    if not isinstance(findings, list) or _has_ref_key(findings, "control_refs") or "compliance_controls" in doc:
        return False
    table: dict[str, dict[str, Any]] = {}
    changed = False
    for position, finding in enumerate(findings):
        controls = finding.get("controls") if isinstance(finding, dict) else None
        if not isinstance(controls, list) or "control_refs" in finding or not all(isinstance(item, dict) for item in controls):
            continue
        refs: list[str] = []
        for control in controls:
            control_id = _control_id(control)
            if table.setdefault(control_id, control) != control:
                break
            refs.append(control_id)
        else:
            findings[position] = {
                ("control_refs" if key == "controls" else key): (refs if key == "controls" else value) for key, value in finding.items()
            }
            changed = True
    if table:
        doc["compliance_controls"] = table
    return changed
