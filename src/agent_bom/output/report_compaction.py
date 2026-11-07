"""Remove exact compatibility copies while retaining canonical evidence tables."""

from typing import Any


def compact_report_sections(report: dict[str, Any]) -> dict[str, Any]:
    """Copy the envelope, removing only aliases proven equal to their target.

    Package occurrences and the standalone inventory replay schema remain
    intact. Distinct legacy content is never discarded on the assumption that
    it must be another copy.
    """
    result = dict(report)
    # Root packages is a public JSON contract, even when it aliases the entity table.
    if "blast_radius" in result and result.get("blast_radii") == result["blast_radius"]:
        result.pop("blast_radii", None)
    return result
