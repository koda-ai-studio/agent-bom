"""Vendor best-practice failures carry controls only for an exact, curated rule."""

from agent_bom.finding import FindingSource, FindingType
from agent_bom.framework_mapping import controls_for_finding_shape
from tests.cloud import test_supabase_inventory as supabase_fixture
from tests.cloud import test_vercel_inventory as vercel_fixture


def shape(rule_id):
    return controls_for_finding_shape(FindingType.CLOUD_BEST_PRACTICE_FAIL, source=FindingSource.CLOUD_SECURITY, rule_id=rule_id)


def test_curated_rules_map_and_unlisted_rules_stay_unmapped():
    assert shape("vercel.git_fork_protection") == {"soc2_tags": ["CC8.1"]}
    assert shape("rls_disabled_in_public")["nist_800_53_tags"] == ["AC-3"]
    assert shape("function_search_path_mutable") == {}
    assert shape(None) == {}
    # The rule table never applies to another finding type with a coincident id.
    assert controls_for_finding_shape(FindingType.CIS_FAIL, source=FindingSource.CLOUD_SECURITY, rule_id="rls_disabled_in_public") == {}


def test_vercel_finding_is_tagged_and_applicable():
    report, _ = vercel_fixture.collect()
    [finding] = report["findings"]
    assert finding["nist_800_53_tags"] == []
    assert finding["soc2_tags"] == ["CC8.1"]
    assert finding["applicable_frameworks"] == ["soc2"]


def test_supabase_advisor_is_tagged_only_for_mapped_rules():
    report, _ = supabase_fixture.collect()
    assert report["findings"][0]["nist_800_53_tags"] == ["AC-3"]
    unmapped = {**supabase_fixture.lint(), "name": "function_search_path_mutable"}
    report, _ = supabase_fixture.collect(advisors={"lints": [unmapped]})
    assert report["findings"][0]["nist_800_53_tags"] == []
    assert report["findings"][0]["applicable_frameworks"] == []
