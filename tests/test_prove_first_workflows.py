"""First-use recipes execute through MCP and retain bounded, scoped evidence."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("is_error,body", [(True, {}), (False, {"error": {"code": "AGENTBOM_MCP_NOT_FOUND_RESOURCE"}})])
def test_workflow_proof_rejects_transport_and_domain_errors(monkeypatch, is_error, body):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    from prove_first_workflows import payload

    response = SimpleNamespace(is_error=is_error, content=[SimpleNamespace(text=json.dumps(body))])
    with pytest.raises(RuntimeError):
        payload(response)


def test_three_first_workflows_over_real_mcp_preserve_evidence(tmp_path):
    output = tmp_path / "investigation"
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    env["PYTHONPATH"] = str(ROOT / "src")
    command = [sys.executable, str(ROOT / "scripts/prove_first_workflows.py"), "--output-dir", str(output)]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr
    proof = json.loads((output / "workflow-proof.json").read_text())
    assert proof["evidence_origin"] == "fictional_agent_configuration"
    assert proof["transport"] == "mcp_stdio"
    assert proof["first_useful_result_seconds"] > 0
    assert proof["deployment_verified"] is False
    for receipt in proof["inputs"]:
        assert hashlib.sha256((output / receipt["manifest_file"]).read_bytes()).hexdigest() == receipt["manifest_sha256"]
    affected = json.loads((output / "affected-agents.json").read_text())
    assert affected["total"] == len(affected["items"]) == 1
    assert affected["tenant_id"] == proof["tenant_id"]
    assert affected["items"][0]["entityType"] == "agent"
    assert affected["interpretation"]["execution"] == "not_established"
    assert affected["interpretation"]["collection_coverage"] == "unknown"
    exposure = json.loads((output / "exposure-evidence.json").read_text())
    assert exposure["scan_id"] == affected["scan_id"] == "first-before"
    assert exposure["snapshot_generation"] == affected["snapshot_generation"]
    assert exposure["tenant_id"] == affected["tenant_id"]
    assert len(exposure["paths"]) == 1
    path = exposure["paths"][0]
    assert path["relationships"]
    edges = {edge["id"]: edge for edge in exposure["edges"]}
    assert all(edges[edge["id"]]["evidence"] and edge["direction"] for edge in path["relationships"])
    delta = json.loads((output / "comparison.json").read_text())
    assert (delta["old"], delta["new"]) == ("first-before", "first-after")
    assert delta["summary"]["nodes_by_entity_type"]["vulnerability"]["removed"] == 1
    assert delta["summary"]["nodes_by_entity_type"].get("agent", {}).get("removed", 0) == 0
    assert proof["strict_argument_rejection"] is True
    saved = {p.name: p.read_bytes() for p in output.glob("*.json")}
    repeated = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    assert repeated.returncode != 0
    assert saved == {p.name: p.read_bytes() for p in output.glob("*.json")}
