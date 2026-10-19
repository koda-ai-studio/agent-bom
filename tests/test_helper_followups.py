"""Fresh-process imports and emitted ISO controls stay usable."""

import subprocess
import sys

import pytest


def test_enrichment_can_be_the_first_package_import():
    result = subprocess.run([sys.executable, "-c", "import agent_bom.enrichment"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "rule_id",
    [
        "PUBLIC_EXPOSED_KEV",
        "PUBLIC_EXPOSED_RCE",
        "PUBLIC_EXPOSED_NETWORK_EXPLOITABLE",
        "PUBLIC_EXPOSED_VULNERABLE",
        "PUBLIC_TO_SENSITIVE_DATA",
        "OVERPERMISSIONED_TO_SENSITIVE",
        "AGENT_REACHES_PRIVILEGED",
        "PUBLIC_PERMISSION_LATERAL",
    ],
)
def test_toxic_rule_iso_crosswalk_tags_reach_scoring(rule_id):
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, control_key_for_tag, rows_by_control_key, scoring_catalog
    from agent_bom.finding import FindingSource, FindingType
    from agent_bom.framework_mapping import controls_for_finding_shape

    metadata = next(item for item in TAG_MAPPED_FRAMEWORKS if item.slug == "iso-27001")
    catalog = scoring_catalog(metadata)
    tags = controls_for_finding_shape(FindingType.COMBINATION, source=FindingSource.GRAPH_ANALYSIS, rule_id=rule_id)["iso_27001_tags"]
    row = {"id": "toxic-test", "severity": "high", "iso_27001_tags": tags}
    grouped = rows_by_control_key([row], catalog, metadata.tag_field)
    for tag in tags:
        key = control_key_for_tag(tag, catalog)
        assert key is not None, f"{rule_id} silently drops {tag}"
        assert grouped[key] == [row]
