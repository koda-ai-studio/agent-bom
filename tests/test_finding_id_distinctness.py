"""Invariant: distinct findings get distinct ids, identical inputs keep one id.

A finding id is the dedupe key every server surface (summary counts,
``/v1/findings``, hub ingest) collapses on. A builder whose key omits the field
that tells two findings apart silently drops real findings server-side while the
CLI still counts them.
"""

from __future__ import annotations

from dataclasses import asdict

import pytest
from starlette.testclient import TestClient

from agent_bom.finding import (
    ast_flow_dict_to_finding,
    cloud_org_architecture_finding_to_finding,
    iac_finding_to_finding,
    secret_dict_to_finding,
)
from agent_bom.iac.kubernetes import scan_k8s_text
from agent_bom.mcp_tool_rules import mcp_rule_finding_to_finding
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_CAPS_MANIFEST = """\
apiVersion: v1
kind: Pod
metadata:
  name: caps
  namespace: prod
spec:
  containers:
    - name: app
      image: registry.example/app:1.0
      securityContext:
        capabilities:
          add: ["NET_RAW", "SYS_ADMIN", "ALL"]
"""


def _k8s_018_findings() -> list[dict]:
    return [asdict(f) for f in scan_k8s_text(_CAPS_MANIFEST, "deploy/caps.yaml") if f.rule_id == "K8S-018"]


def test_flow_style_capabilities_share_a_line_but_not_an_id() -> None:
    rows = _k8s_018_findings()
    assert len(rows) == 3
    assert len({row["line_number"] for row in rows}) == 1, "fixture must reproduce the same-line case"
    ids = {iac_finding_to_finding(row).id for row in rows}
    assert len(ids) == 3


def test_iac_id_is_stable_for_identical_input() -> None:
    row = _k8s_018_findings()[0]
    assert iac_finding_to_finding(dict(row)).id == iac_finding_to_finding(dict(row)).id


_IAC_BASE = {
    "rule_id": "K8S-018",
    "severity": "critical",
    "title": "Dangerous capability NET_RAW added",
    "message": "Container 'app' adds capability NET_RAW.",
    "file_path": "deploy/caps.yaml",
    "line_number": 12,
    "category": "kubernetes",
}

_SECRET_BASE = {"file": "app/settings.py", "line": 4, "type": "AWS Access Key", "category": "credential", "severity": "critical"}

_FLOW_BASE = {
    "category": "tainted_command_execution",
    "file": "server/tools.py",
    "line": 20,
    "entrypoint": "run_tool",
    "sink": "subprocess.run",
}

_ORG_BASE = {"check_id": "ORG-001", "title": "No SCP", "severity": "high"}

_MCP_RULE_BASE = {"rule_id": "MCP-TOOL-001", "tool_name": "read_file", "property_name": "path", "severity": "high"}

# (builder, base input, keyword args, identity-bearing variations). Each
# variation changes one field that names a different real finding.
_BUILDERS = [
    pytest.param(
        iac_finding_to_finding,
        _IAC_BASE,
        {},
        [
            {"rule_id": "K8S-019"},
            {"file_path": "deploy/other.yaml"},
            {"line_number": 13},
            {"title": "Dangerous capability SYS_ADMIN added", "message": "Container 'app' adds capability SYS_ADMIN."},
            {"message": "Container 'sidecar' adds capability NET_RAW."},
        ],
        id="iac",
    ),
    pytest.param(
        secret_dict_to_finding,
        _SECRET_BASE,
        {},
        [{"file": "app/other.py"}, {"line": 5}, {"type": "GitHub Token"}, {"category": "pii"}],
        id="secret",
    ),
    pytest.param(
        ast_flow_dict_to_finding,
        _FLOW_BASE,
        {},
        [{"file": "server/b.py"}, {"line": 21}, {"entrypoint": "other_tool"}, {"sink": "os.system"}, {"category": "tainted_sql"}],
        id="ast-flow",
    ),
    pytest.param(
        cloud_org_architecture_finding_to_finding,
        _ORG_BASE,
        {"provider": "aws", "org_id": "o-example"},
        [{"check_id": "ORG-002"}],
        id="cloud-org",
    ),
    pytest.param(
        mcp_rule_finding_to_finding,
        _MCP_RULE_BASE,
        {"tool_name": "read_file", "server_name": "fs-a"},
        [{"rule_id": "MCP-TOOL-002"}, {"tool_name": "write_file"}, {"property_name": "mode"}],
        id="mcp-tool-rule",
    ),
]


@pytest.mark.parametrize(("builder", "base", "kwargs", "variations"), _BUILDERS)
def test_builders_give_distinct_findings_distinct_ids(builder, base, kwargs, variations) -> None:
    base_id = builder(dict(base), **kwargs).id
    assert builder(dict(base), **kwargs).id == base_id, "identical input must keep one id"
    ids = [base_id] + [builder({**base, **change}, **kwargs).id for change in variations]
    assert len(set(ids)) == len(ids), list(zip(["base", *map(str, variations)], ids, strict=True))


def test_same_tool_rule_on_two_servers_is_two_findings() -> None:
    first = mcp_rule_finding_to_finding(dict(_MCP_RULE_BASE), tool_name="read_file", server_name="fs-a")
    second = mcp_rule_finding_to_finding(dict(_MCP_RULE_BASE), tool_name="read_file", server_name="fs-b")
    assert first.id != second.id


def test_same_tool_rule_with_distinct_tool_identity_is_two_findings() -> None:
    first = mcp_rule_finding_to_finding(dict(_MCP_RULE_BASE), tool_name="read_file", tool_stable_id="tool-a", server_name="fs")
    second = mcp_rule_finding_to_finding(dict(_MCP_RULE_BASE), tool_name="read_file", tool_stable_id="tool-b", server_name="fs")
    assert first.id != second.id


class TestPushedDistinctFindingsAllCount:
    def setup_method(self) -> None:
        from agent_bom.api.server import set_job_store
        from agent_bom.api.store import InMemoryJobStore

        enable_trusted_proxy_env()
        set_job_store(InMemoryJobStore())

    def teardown_method(self) -> None:
        disable_trusted_proxy_env()

    def test_summary_and_findings_api_keep_every_distinct_iac_finding(self) -> None:
        from agent_bom.api.server import app

        rows = _k8s_018_findings()
        findings = [iac_finding_to_finding(row).to_dict() for row in rows]
        client = TestClient(app)
        headers = proxy_headers(role="admin", tenant="tenant-iac-distinct")
        response = client.post("/v1/results/push", json={"source_id": "iac-distinct", "findings": findings}, headers=headers)
        assert response.status_code == 201, response.text

        job = client.get(f"/v1/scan/{response.json()['job_id']}", params={"view": "full"}, headers=headers).json()
        assert job["result"]["summary"]["total_findings"] == len(rows) == 3
        listed = client.get("/v1/findings", params={"limit": 50, "offset": 0}, headers=headers)
        assert listed.status_code == 200, listed.text
        assert listed.json()["total"] == 3
