"""IaC findings carry only compliance IDs for the provider that owns the resource.

A CIS AWS control on an Azure or GCP resource is a wrong compliance claim: it
counts toward a framework the resource is not in scope for. Generic rules pick
provider-specific IDs from the resource type; every rule registry is checked
so a new rule cannot reintroduce the leak.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_bom.iac import terraform_security as tf
from agent_bom.iac.cloudformation import CFN_RULES
from agent_bom.iac.terraform_security_common import TfResource

_PROVIDER_CIS_PREFIXES = {"CIS-AWS-": "aws_", "CIS-Azure-": "azurerm_", "CIS-GCP-": "google_"}
_GENERIC_SAMPLE_TYPES = ("aws_db_instance", "azurerm_mssql_server", "google_sql_user", "kubernetes_secret", "random_password")
_TRIGGER_BLOCKS = (
    "",
    """
  password       = "NotARealPassw0rd-demo"
  admin_password = "NotARealPassw0rd-demo"
  public_key     = "ssh-rsa AAAAexampleonlynotarealkey user"
  cidr_blocks    = ["0.0.0.0/0"]
  acl            = "public-read"
  publicly_accessible = true
  policy = <<EOF
{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
EOF
""",
)


def _resource(rtype: str, block: str) -> TfResource:
    content = f'resource "{rtype}" "r" {{{block}}}\n'
    return TfResource(
        rtype=rtype,
        rname="r",
        block=block,
        block_start_line=1,
        rel_path="main.tf",
        content=content,
        block_offset=content.index("{") + 1,
    )


def _cross_provider_ids(rtype: str, compliance: list[str]) -> list[str]:
    return [
        cid
        for cid in compliance
        for prefix, owner in _PROVIDER_CIS_PREFIXES.items()
        if cid.startswith(prefix) and not rtype.startswith(owner)
    ]


def _registry_findings():
    for scope, check in tf._RULES:
        for rtype in sorted(scope) if scope is not None else _GENERIC_SAMPLE_TYPES:
            for block in _TRIGGER_BLOCKS:
                for finding in check(_resource(rtype, block)):
                    yield rtype, finding


def test_terraform_rules_never_tag_another_providers_cis_controls():
    leaks = [(f.rule_id, rtype, _cross_provider_ids(rtype, f.compliance)) for rtype, f in _registry_findings()]
    assert [leak for leak in leaks if leak[2]] == []


def test_generic_terraform_rules_fire_for_every_provider():
    fired = {(rtype.split("_", 1)[0], f.rule_id) for rtype, f in _registry_findings()}
    for provider in ("aws", "azurerm", "google"):
        assert {(provider, "TF-SEC-007"), (provider, "TF-SEC-051")} <= fired


@pytest.mark.parametrize(
    ("rtype", "expected"),
    [
        ("aws_db_instance", ["CIS-AWS-1.14", "NIST-IA-5", "NIST-SC-28"]),
        ("azurerm_mssql_server", ["NIST-IA-5", "NIST-SC-28"]),
        ("google_sql_user", ["NIST-IA-5", "NIST-SC-28"]),
    ],
)
def test_hardcoded_secret_compliance_is_provider_scoped(rtype, expected):
    findings = tf._secrets.tf_sec_051(_resource(rtype, '\n  password = "NotARealPassw0rd-demo"\n'))

    assert [f.compliance for f in findings] == [expected]


def test_cloudformation_rules_are_aws_scoped():
    assert all(rtype.startswith("AWS::") for rtypes, _ in CFN_RULES for rtype in rtypes)


def test_non_cloud_iac_rule_sets_carry_no_cloud_cis_ids():
    iac_dir = Path(tf.__file__).parent
    cloud_scoped = re.compile(r"^(terraform_security|cloudformation)")
    cis_cloud = re.compile(r"CIS-(?:AWS|Azure|GCP)-")
    offenders = [p.name for p in iac_dir.glob("*.py") if not cloud_scoped.match(p.name) and cis_cloud.search(p.read_text())]
    assert offenders == []


def test_azure_administrator_login_password_is_detected(tmp_path):
    path = tmp_path / "main.tf"
    path.write_text('resource "azurerm_mssql_server" "db" {\n  administrator_login_password = "NotARealPassw0rd-demo"\n}\n')

    findings = tf.scan_terraform_security(path)

    assert [(f.rule_id, f.line_number, f.compliance) for f in findings] == [("TF-SEC-051", 2, ["NIST-IA-5", "NIST-SC-28"])]


@pytest.mark.parametrize("key", ["ssh-keys", '"ssh-keys"'])
def test_gcp_metadata_ssh_keys_is_detected(tmp_path, key):
    path = tmp_path / "main.tf"
    path.write_text(
        'resource "google_compute_instance" "vm" {\n'
        "  metadata = {\n"
        f'    {key} = "admin:ssh-ed25519 AAAAexampleonlynotarealkey admin"\n'
        "  }\n"
        "}\n"
    )

    findings = tf.scan_terraform_security(path)

    assert [(f.rule_id, f.compliance) for f in findings] == [("TF-SEC-007", ["NIST-IA-5"])]


def test_gcp_block_project_ssh_keys_flag_is_not_a_key(tmp_path):
    path = tmp_path / "main.tf"
    path.write_text('resource "google_compute_instance" "vm" {\n  metadata = {\n    block-project-ssh-keys = "true"\n  }\n}\n')

    assert tf.scan_terraform_security(path) == []


def _iac_sarif(findings: list[dict]) -> dict:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.sarif import to_sarif

    report = AIBOMReport(scan_id="iac-provider-scope")
    report.iac_findings_data = {"findings": findings}
    return to_sarif(report)


def _tf_051(rname: str, rtype: str, line: int, compliance: list[str]) -> dict:
    return {
        "rule_id": "TF-SEC-051",
        "severity": "critical",
        "title": "Hardcoded secret in Terraform resource",
        "message": f"Resource '{rname}' ({rtype}) sets 'password' to a literal value.",
        "file_path": "main.tf",
        "line_number": line,
        "category": "terraform",
        "compliance": compliance,
    }


def test_sarif_iac_rule_is_instance_independent():
    sarif = _iac_sarif(
        [
            _tf_051("db", "azurerm_mssql_server", 2, ["NIST-IA-5", "NIST-SC-28"]),
            _tf_051("rds", "aws_db_instance", 9, ["CIS-AWS-1.14", "NIST-IA-5", "NIST-SC-28"]),
        ]
    )
    run = sarif["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "iac/TF-SEC-051")
    results = [r for r in run["results"] if r["ruleId"] == "iac/TF-SEC-051"]

    assert rule["fullDescription"]["text"] == "Hardcoded secret in Terraform resource"
    assert rule["properties"]["compliance"] == ["NIST-IA-5", "NIST-SC-28"]
    assert [r["properties"]["compliance"] for r in results] == [
        ["NIST-IA-5", "NIST-SC-28"],
        ["CIS-AWS-1.14", "NIST-IA-5", "NIST-SC-28"],
    ]
    assert results[0]["message"]["text"].startswith("Resource 'db' (azurerm_mssql_server)")
