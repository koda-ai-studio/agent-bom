"""Provider retirement must stop credentials/probes without claiming freshness."""

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_retired_smithery_publisher_cannot_use_credentials_or_create_releases():
    workflow = (ROOT / ".github/workflows/publish-registries.yml").read_text()
    jobs = yaml.safe_load(workflow)["jobs"]
    assert "smithery" not in jobs
    assert "SMITHERY_API_TOKEN" not in workflow
    assert "api.smithery.ai" not in workflow
    assert "https://www.smithery.ai/future" in workflow
    assert {"release", "glama", "clawhub"} <= jobs.keys()


@pytest.mark.parametrize("active_status,expected_exit", [("fresh", 0), ("stale", 1), ("fresh_degraded", 1)])
def test_retired_provider_is_reported_without_network_and_active_gates_stay_strict(monkeypatch, tmp_path, active_status, expected_exit):
    spec = importlib.util.spec_from_file_location("surface_retirement_test", ROOT / "scripts/check_surface_freshness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def forbidden(*args, **kwargs):
        pytest.fail("Retired Smithery surface must not contact the former provider")

    monkeypatch.setattr(module, "probe_smithery", forbidden)
    for name in ["probe_pypi", "probe_mcp_registry", "probe_docker", "probe_glama"]:
        monkeypatch.setattr(module, name, lambda *a, **kw: {"surface": "Active provider", "status": active_status})
    out = tmp_path / "report.json"
    assert module.main(["--expected", "0.113.2", "--retired-smithery", "--fail-on-stale", "--out", str(out)]) == expected_exit
    report = json.loads(out.read_text())
    retired = next(row for row in report["surfaces"] if row["surface"] == "Smithery")
    assert retired["status"] == "retired"
    assert retired["required"] is False
    assert retired["retired_at"] == "2026-10-31"
    assert retired["notice_url"] == "https://www.smithery.ai/future"
    assert report["all_fresh"] is False
    assert report["all_required_fresh"] is (expected_exit == 0)


def test_scheduled_monitors_explicitly_record_provider_retirement():
    for name in ["surface-freshness.yml", "deployment-freshness.yml"]:
        workflow = (ROOT / ".github/workflows" / name).read_text()
        assert "--retired-smithery" in workflow


def test_retirement_guide_has_working_direct_client_path():
    guide = (ROOT / "site-docs/integrations/smithery.md").read_text()
    assert "October 31, 2026" in guide
    assert "https://www.smithery.ai/future" in guide
    assert "agent-bom mcp server" in guide
    assert "https://agent-bom-mcp.up.railway.app/mcp" in guide
    assert "ready for Smithery publication" not in guide


def test_retirement_rejects_live_schema_export_before_network(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("retired_export_test", ROOT / "scripts/check_surface_freshness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def forbidden(*args, **kwargs):
        pytest.fail("Retired provider must not receive a live request")

    monkeypatch.setattr(module, "_http_json", forbidden)
    with pytest.raises(SystemExit) as exc:
        module.main(["--retired-smithery", "--write-smithery-tool-contract", str(tmp_path / "contract.json")])
    assert exc.value.code == 2
    assert not (tmp_path / "contract.json").exists()
