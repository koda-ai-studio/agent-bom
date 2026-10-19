"""Current-estate remediation must count the credentials its findings expose."""

from __future__ import annotations

from agent_bom.api.remediation_view import current_remediation_response, remediation_finding_projection


def _row(**overrides):
    row = {
        "cve_id": "CVE-2023-32681",
        "package_name": "requests",
        "package_version": "2.28.0",
        "ecosystem": "pypi",
        "severity": "medium",
        "fixed_version": "2.31.0",
        "affected_agents": ["langchain-service"],
        "exposed_credentials": ["DATABASE_URL", "PINECONE_API_KEY"],
        "exposed_tools": ["query"],
    }
    row.update(overrides)
    return row


def test_projection_keeps_credential_and_tool_names_but_never_values():
    projected = remediation_finding_projection(_row(evidence={"env": {"DATABASE_URL": "postgres://user:hunter2@db/prod"}}))
    assert projected["exposed_credentials"] == ["DATABASE_URL", "PINECONE_API_KEY"]
    assert projected["exposed_tools"] == ["query"]
    assert "hunter2" not in repr(projected)


def test_projection_drops_values_that_look_like_secrets_not_names():
    projected = remediation_finding_projection(_row(exposed_credentials=["DATABASE_URL", "postgres://user:hunter2@db/prod"]))
    assert projected["exposed_credentials"] == ["DATABASE_URL"]


def test_current_plan_reports_the_credentials_each_package_exposes():
    rows = [
        remediation_finding_projection(_row()),
        remediation_finding_projection(_row(cve_id="CVE-2024-35195", exposed_credentials=["OPENAI_API_KEY"])),
    ]
    plan = current_remediation_response({"findings": rows, "completeness": {"status": "complete"}}).remediation_plan
    [item] = [entry for entry in plan if entry["package"] == "requests"]
    assert sorted(item["exposed_credentials"]) == ["DATABASE_URL", "OPENAI_API_KEY", "PINECONE_API_KEY"]
