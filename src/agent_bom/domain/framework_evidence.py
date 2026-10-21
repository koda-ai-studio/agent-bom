"""Which frameworks a finding row is evidence for: the one definition framework counts and drill-throughs share."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, normalize_framework_slug, scored_control_codes


def _framework_control_codes(row: Mapping[str, Any], tag_field: str, framework_key: str) -> set[str]:
    """Collect one framework's control codes from every representation on a row.

    A scan finding may carry its framework controls three ways: the per-framework
    tag list (``soc2_tags``), the structured ``controls`` list, and the flattened
    ``framework_tags`` (``"soc2:CC6.1"``). All are read, but strictly scoped to
    ``framework_key`` so a code is never matched against another framework's
    namespace — the flat ``compliance_tags`` union is deliberately NOT consulted.
    """
    codes: set[str] = set()
    raw = row.get(tag_field)
    if isinstance(raw, (list, tuple, set)):
        codes.update(str(tag) for tag in raw)
    controls = row.get("controls")
    if isinstance(controls, list):
        for control in controls:
            if isinstance(control, dict) and str(control.get("framework") or "") == framework_key:
                code = control.get("control") or control.get("id")
                if code:
                    codes.add(str(code))
    framework_tags = row.get("framework_tags")
    if isinstance(framework_tags, list):
        prefix = f"{framework_key}:"
        for tag in framework_tags:
            text = str(tag)
            if text.startswith(prefix):
                codes.add(text[len(prefix) :])
    return codes


def framework_evidence_slugs(row: Mapping[str, Any]) -> set[str]:
    """Frameworks a finding row counts toward: the one definition every framework count and drill-through uses.

    A control code the framework's scoring catalog resolves (what
    ``/v1/compliance`` counts) is evidence; a bulk-ingested row may also declare
    the framework in ``applicable_frameworks``. Selection-table applicability on
    a scanned row is not evidence of a control, so it never counts.
    """
    slugs = {
        metadata.slug
        for metadata in TAG_MAPPED_FRAMEWORKS
        if scored_control_codes(
            metadata.tag_field,
            _framework_control_codes(row, metadata.tag_field, metadata.tag_field.removesuffix("_tags")),
        )
    }
    applicable = row.get("applicable_frameworks")
    if row.get("origin") == "bulk_ingest" and isinstance(applicable, (list, tuple, set)):
        slugs.update(normalize_framework_slug(str(item)) for item in applicable if item)
    return slugs


__all__ = ["_framework_control_codes", "framework_evidence_slugs"]
