"""Active registry publication stays serialized and release-bound."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/publish-registries.yml"


def test_registry_publication_runs_are_serialized() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "concurrency:\n  group: publish-registries\n  cancel-in-progress: false" in workflow
    assert "github.event_name == 'schedule'" in workflow.split("  clawhub:\n", 1)[1]


def test_delayed_release_event_cannot_republish_an_older_version_as_latest() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "publish_current: ${{ steps.release.outputs.publish_current }}" in workflow
    assert 'LATEST_RELEASE_TAG=$(gh api "repos/${GITHUB_REPOSITORY}/releases/latest" --jq .tag_name)' in workflow
    assert 'if [ "$LATEST_RELEASE_TAG" != "$RELEASE_TAG" ]; then' in workflow
    assert "publish_current=false" in workflow
    assert workflow.count("needs.release.outputs.publish_current == 'true'") == 2


def test_surface_freshness_rechecks_immediately_after_registry_publication() -> None:
    workflow = (ROOT / ".github/workflows/surface-freshness.yml").read_text(encoding="utf-8")
    assert 'workflows: ["Publish to Registries"]' in workflow
    job = yaml.safe_load(workflow)["jobs"]["freshness"]
    assert "github.event_name != 'workflow_run'" in job["if"]
    assert 'contains(fromJSON(\'["success","failure"]\'), github.event.workflow_run.conclusion)' in job["if"]
