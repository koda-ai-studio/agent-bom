"""Real-project onboarding must retain scoped evidence without writing samples."""

from __future__ import annotations

import hashlib
import json
import shlex
import stat
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import click
import pytest
from click.testing import CliRunner

from agent_bom.cli import main


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "customer project"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.32.3\n")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "control.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    monkeypatch.setenv("AGENT_BOM_TENANT_ID", "activation-test")
    return root


@pytest.fixture
def scan(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        Path(args[args.index("-o") + 1]).write_text(json.dumps({"scan_id": "selected /scan?", "scan_run": {"outcome": "complete"}}))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("agent_bom.cli._quickstart._resolve_agent_bom", lambda: "agent-bom")
    monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", run)
    monkeypatch.setattr(
        "agent_bom.cli._quickstart._verify_persisted_graph",
        lambda **kwargs: {"scan_id": "selected /scan?", "nodes": 3, "edges": 2},
    )
    monkeypatch.setattr("agent_bom.cli._quickstart._persist_completed_scan", lambda *args: None)
    return calls


def test_project_plan_is_read_only_and_shell_safe(project, tmp_path, scan):
    destination = tmp_path / "private evidence"
    result = CliRunner().invoke(
        main, ["quickstart", "--project", str(project), "--evidence-dir", str(destination), "--offline", "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    command = next(line.strip() for line in result.output.splitlines() if line.strip().startswith("agent-bom quickstart"))
    parsed = shlex.split(command)
    assert parsed[parsed.index("--project") + 1] == str(project)
    assert "--run" in parsed and "--offline" in parsed
    assert "package-CVE lookup" in result.output
    assert "project-scoped" in result.output.lower()
    assert not destination.exists() and not scan
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("offline", [False, True])
def test_project_activation_persists_private_receipt_and_exact_links(project, tmp_path, scan, offline):
    before = {path.name: path.read_bytes() for path in project.iterdir()}
    destination = tmp_path / "private evidence"
    args = ["quickstart", "--run", "--project", str(project), "--evidence-dir", str(destination), "--port", "8522"]
    result = CliRunner().invoke(main, args + (["--offline"] if offline else []))
    assert result.exit_code == 0, result.output
    command, options = scan[0]
    assert command[command.index("-p") + 1] == str(project)
    assert "--no-discover" in command and "--context-graph" in command and "--exit-zero" in command
    assert "--inventory" not in command and "--enrich" not in command
    assert ("--no-scan" in command) == offline
    assert ("--offline" in command) == offline
    assert options["timeout"] == 300
    assert options["env"]["AGENT_BOM_GRAPH_DB"] == str(tmp_path / "graph.db")
    assert {path.name: path.read_bytes() for path in project.iterdir()} == before
    assert not (destination / "gateway-baseline-policy.json").exists()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    receipt_path = destination / "activation.json"
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
    receipt = json.loads(receipt_path.read_text())
    assert receipt["schema_version"] == "project-activation.v1"
    assert receipt["tenant_id"] == "activation-test"
    assert receipt["graph"] == {"scan_id": "selected /scan?", "nodes": 3, "edges": 2}
    assert receipt["report_sha256"] == hashlib.sha256((destination / "report.json").read_bytes()).hexdigest()
    assert receipt["package_cve_lookup"] == ("skipped" if offline else "requested")
    for key, route in (("findings", "/findings"), ("investigation", "/security-graph")):
        link = urlsplit(receipt["links"][key])
        assert link.netloc == "127.0.0.1:8522" and link.path == route
        assert parse_qs(link.query)["scan"] == ["selected /scan?"]
        assert receipt["links"][key] in result.output
    assert "Project activation complete" in result.output
    assert "Sample evidence" not in result.output
    assert "--persist" in result.output and "--api-key" in result.output
    assert "--allow-insecure-no-auth" not in result.output
    assert "authenticated API-key/OIDC principal for tenant activation-test" in result.output


@pytest.mark.parametrize("option", ["--force", "--write-sample", "--gateway-policy", "--gateway-mode"])
def test_project_rejects_sample_options_before_writes(project, tmp_path, scan, option):
    args = ["quickstart", "--project", str(project), "--run", option]
    if option == "--gateway-mode":
        args.append("enforce")
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2, result.output
    assert "sample" in result.output.lower()
    assert not scan and not (tmp_path / "state").exists()


@pytest.mark.parametrize("inside", [False, True])
def test_project_refuses_existing_or_in_project_evidence(project, tmp_path, scan, inside):
    destination = project / "evidence" if inside else tmp_path / "existing"
    if not inside:
        destination.mkdir()
        (destination / "report.json").write_text("retain me")
    result = CliRunner().invoke(main, ["quickstart", "--project", str(project), "--run", "--evidence-dir", str(destination)])
    assert result.exit_code != 0
    assert not scan
    if inside:
        assert not destination.exists()
    else:
        assert (destination / "report.json").read_text() == "retain me"


@pytest.mark.parametrize("stage", ["scan", "graph", "job"])
def test_project_failure_keeps_evidence_without_completion_receipt(project, tmp_path, scan, monkeypatch, stage):
    def fail(*args, **kwargs):
        raise click.ClickException("evidence unavailable")

    if stage == "scan":
        monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 2))
    else:
        name = "_verify_persisted_graph" if stage == "graph" else "_persist_completed_scan"
        monkeypatch.setattr(f"agent_bom.cli._quickstart.{name}", fail)
    destination = tmp_path / "failed evidence"
    result = CliRunner().invoke(main, ["quickstart", "--project", str(project), "--run", "--evidence-dir", str(destination)])
    assert result.exit_code != 0
    assert "Project activation complete" not in result.output
    assert not (destination / "activation.json").exists()
    assert destination.is_dir()
    if stage != "scan":
        assert (destination / "report.json").is_file()


def test_project_default_runs_have_distinct_retained_artifacts(project, tmp_path, scan):
    for _ in range(2):
        result = CliRunner().invoke(main, ["quickstart", "--project", str(project), "--run", "--offline"])
        assert result.exit_code == 0, result.output
    receipts = list((tmp_path / "state" / "activations").glob("*/activation.json"))
    assert len(receipts) == 2


def test_evidence_dir_requires_project(tmp_path):
    result = CliRunner().invoke(main, ["quickstart", "--evidence-dir", str(tmp_path / "new")])
    assert result.exit_code == 2
    assert "--project" in result.output


def test_real_project_scan_retains_exact_job_and_graph(project, tmp_path):
    from agent_bom.api.store import SQLiteJobStore
    from agent_bom.db.graph_store import load_graph, open_graph_db

    destination = tmp_path / "real evidence"
    before = {path.name: path.read_bytes() for path in project.iterdir()}
    result = CliRunner().invoke(main, ["quickstart", "--project", str(project), "--run", "--offline", "--evidence-dir", str(destination)])
    assert result.exit_code == 0, result.output
    receipt = json.loads((destination / "activation.json").read_text())
    report = json.loads((destination / "report.json").read_text())
    scan_id = report["scan_id"]
    assert receipt["graph"]["scan_id"] == scan_id
    assert receipt["package_cve_lookup"] == "skipped"
    assert "zero" not in result.output.lower() or "not a clean" in result.output
    job = SQLiteJobStore(str(tmp_path / "control.db")).get(scan_id, tenant_id="activation-test")
    assert job is not None and job.result == report and job.status.value == "done"
    assert SQLiteJobStore(str(tmp_path / "control.db")).get(scan_id, tenant_id="other") is None
    with open_graph_db(tmp_path / "graph.db") as connection:
        graph = load_graph(connection, tenant_id="activation-test", scan_id=scan_id)
    assert len(graph.nodes) == receipt["graph"]["nodes"] > 0
    assert len(graph.edges) == receipt["graph"]["edges"] > 0
    assert {path.name: path.read_bytes() for path in project.iterdir()} == before
    assert stat.S_IMODE((destination / "report.json").stat().st_mode) == 0o600


@pytest.mark.parametrize("variable", ["AGENT_BOM_DB", "AGENT_BOM_GRAPH_DB", "AGENT_BOM_STATE_DIR"])
def test_project_refuses_state_writes_inside_target(project, scan, monkeypatch, variable):
    monkeypatch.setenv(variable, str(project / "state"))
    result = CliRunner().invoke(main, ["quickstart", "--project", str(project), "--run"])
    assert result.exit_code != 0
    assert "outside the selected project" in result.output
    assert not scan and not (project / "state").exists()


def test_project_requires_explicit_tenant_for_shared_deployment(project, scan, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_TENANT_ID")
    monkeypatch.setenv("AGENT_BOM_REQUIRE_TENANT_BOUNDARY", "1")
    result = CliRunner().invoke(main, ["quickstart", "--project", str(project), "--run"])
    assert result.exit_code != 0
    assert "explicit tenant" in result.output
    assert not scan


def test_project_default_tenant_handoff_uses_loopback_analyst(project, scan, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TENANT_ID", "default")
    result = CliRunner().invoke(main, ["quickstart", "--project", str(project), "--run", "--offline"])
    assert result.exit_code == 0, result.output
    assert "--host 127.0.0.1" in result.output
    assert "--allow-insecure-no-auth" in result.output
    assert "AGENT_BOM_NO_AUTH_ROLE=analyst" in result.output
