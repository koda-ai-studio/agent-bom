"""Azure Terraform misconfiguration rules (TF-SEC-1xx).

Positive cases come from the synthetic corpus so the golden snapshot, the
rule-coverage gate and these assertions share one fixture; negatives are the
clean sibling file plus inline edge cases per rule.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from agent_bom.iac.terraform_security import scan_terraform_security

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "iac_golden" / "terraform"
AZURE_RULES = {f"TF-SEC-{n}" for n in range(101, 113)}


def _rules(path: Path) -> Counter[str]:
    return Counter(f.rule_id for f in scan_terraform_security(path))


def _scan(tmp_path: Path, content: str) -> list:
    path = tmp_path / "main.tf"
    path.write_text(content)
    return scan_terraform_security(path)


def test_misconfigured_azure_corpus_fires_every_azure_rule() -> None:
    fired = _rules(FIXTURES / "synthetic_azure_misconfig.tf")
    assert AZURE_RULES <= set(fired), sorted(AZURE_RULES - set(fired))
    assert fired["TF-SEC-101"] == 3  # legacy flag, v4 flag, public container
    assert fired["TF-SEC-104"] == 4  # standalone rule + 3 inline rules
    assert fired["TF-SEC-111"] == 2  # both SQL servers lack an auditing policy


def test_clean_azure_corpus_is_clean() -> None:
    assert _rules(FIXTURES / "synthetic_azure_good.tf") == Counter()


def test_azure_rules_carry_cis_azure_ids_and_remediation() -> None:
    findings = [f for f in scan_terraform_security(FIXTURES / "synthetic_azure_misconfig.tf") if f.rule_id in AZURE_RULES]
    assert findings
    for finding in findings:
        assert finding.remediation, finding.rule_id
        assert finding.category == "terraform"
        assert not any(cid.startswith(("CIS-AWS-", "CIS-GCP-")) for cid in finding.compliance), finding.rule_id
        assert any(cid.startswith("NIST-") for cid in finding.compliance), finding.rule_id
    cis: dict[str, set[str]] = {}
    for f in findings:
        cis.setdefault(f.rule_id, set()).update(c for c in f.compliance if c.startswith("CIS-Azure-"))
    assert cis["TF-SEC-101"] == {"CIS-Azure-3.7"}
    assert cis["TF-SEC-102"] == {"CIS-Azure-3.1"}
    assert cis["TF-SEC-103"] == {"CIS-Azure-3.15"}
    assert cis["TF-SEC-105"] == {"CIS-Azure-4.1.6"}  # SQL only; PostgreSQL/MySQL public access carries NIST ids
    assert cis["TF-SEC-106"] == {"CIS-Azure-4.3.1"}  # PostgreSQL SSL off; the MySQL weak-TLS case is NIST-only
    assert cis["TF-SEC-107"] == {"CIS-Azure-8.3"}
    assert cis["TF-SEC-108"] == {"CIS-Azure-7.3"}
    assert cis["TF-SEC-109"] == set()
    assert cis["TF-SEC-110"] == set()
    assert cis["TF-SEC-111"] == {"CIS-Azure-4.1.1"}
    assert cis["TF-SEC-112"] == {"CIS-Azure-4.1.2"}


def test_nsg_rule_maps_ports_to_the_right_cis_controls(tmp_path: Path) -> None:
    def nsg(port: str, protocol: str = "Tcp") -> list:
        return [
            f
            for f in _scan(
                tmp_path,
                'resource "azurerm_network_security_rule" "r" {\n'
                '  direction              = "Inbound"\n'
                '  access                 = "Allow"\n'
                f'  protocol               = "{protocol}"\n'
                f'  destination_port_range = "{port}"\n'
                '  source_address_prefix  = "*"\n'
                "}\n",
            )
            if f.rule_id == "TF-SEC-104"
        ]

    ssh = nsg("22")
    assert [f.severity for f in ssh] == ["critical"]
    assert "CIS-Azure-6.2" in ssh[0].compliance and "CIS-Azure-6.1" not in ssh[0].compliance
    rdp = nsg("3000-4000")
    assert "CIS-Azure-6.1" in rdp[0].compliance and "CIS-Azure-6.2" not in rdp[0].compliance
    everything = nsg("*", "*")
    assert {"CIS-Azure-6.1", "CIS-Azure-6.2"} <= set(everything[0].compliance)
    other = nsg("8443")
    assert [f.severity for f in other] == ["high"]
    assert not any(c.startswith("CIS-Azure-") for c in other[0].compliance)
    assert "NIST-AC-4" in other[0].compliance
    assert nsg("443") == []


def test_nsg_rule_ignores_deny_outbound_and_scoped_sources(tmp_path: Path) -> None:
    base = (
        'resource "azurerm_network_security_rule" "r" {{\n'
        '  direction              = "{direction}"\n'
        '  access                 = "{access}"\n'
        '  protocol               = "Tcp"\n'
        '  destination_port_range = "22"\n'
        "  {source}\n"
        "}}\n"
    )
    for direction, access, source in (
        ("Inbound", "Deny", 'source_address_prefix = "*"'),
        ("Outbound", "Allow", 'source_address_prefix = "*"'),
        ("Inbound", "Allow", 'source_address_prefix = "10.0.0.0/8"'),
        ("Inbound", "Allow", 'source_address_prefixes = ["10.0.0.0/8", "192.168.0.0/16"]'),
        ("Inbound", "Allow", 'source_address_prefix = "VirtualNetwork"'),
    ):
        findings = _scan(tmp_path, base.format(direction=direction, access=access, source=source))
        assert [f.rule_id for f in findings] == [], (direction, access, source)


@pytest.mark.parametrize(
    ("snippet", "expected"),
    [
        ('  allow_blob_public_access = false\n  enable_https_traffic_only = true\n  min_tls_version = "TLS1_2"\n', set()),
        ("", set()),  # provider defaults differ by major version; absence is not asserted as public
        ("  allow_nested_items_to_be_public = true\n", {"TF-SEC-101"}),
        ("  https_traffic_only_enabled = false\n", {"TF-SEC-102"}),
        ('  min_tls_version = "TLS1_1"\n', {"TF-SEC-103"}),
        ("  min_tls_version = var.tls\n", set()),
    ],
)
def test_storage_account_flags(tmp_path: Path, snippet: str, expected: set[str]) -> None:
    findings = _scan(tmp_path, 'resource "azurerm_storage_account" "s" {\n' + snippet + "}\n")
    assert {f.rule_id for f in findings} == expected


def test_storage_public_access_points_at_the_offending_line(tmp_path: Path) -> None:
    findings = _scan(tmp_path, 'resource "azurerm_storage_account" "s" {\n  name = "x"\n  allow_blob_public_access = true\n}\n')
    assert [(f.rule_id, f.line_number, f.severity) for f in findings] == [("TF-SEC-101", 3, "critical")]


def test_sql_public_access_default_is_reported_as_default(tmp_path: Path) -> None:
    findings = _scan(tmp_path, 'resource "azurerm_mssql_server" "s" {\n  name = "s"\n}\n')
    public = [f for f in findings if f.rule_id == "TF-SEC-105"]
    assert len(public) == 1
    assert "defaults to true" in public[0].message
    assert findings[-1].rule_id == "TF-SEC-111"


def test_flexible_server_with_delegated_subnet_is_private(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'resource "azurerm_postgresql_flexible_server" "f" {\n  delegated_subnet_id = "s"\n  private_dns_zone_id = "z"\n}\n',
    )
    assert findings == []


def test_aws_rules_do_not_fire_on_azure_resources() -> None:
    for name in ("synthetic_azure_misconfig.tf", "synthetic_azure_good.tf"):
        fired = {f.rule_id for f in scan_terraform_security(FIXTURES / name)}
        assert not {r for r in fired if r.startswith("TF-SEC-0") and r not in {"TF-SEC-007", "TF-SEC-051"}}, name
        assert not {r for r in fired if r.startswith("TF-SEC-2")}, name


def test_azure_rules_do_not_fire_on_aws_resources() -> None:
    fired = {f.rule_id for f in scan_terraform_security(FIXTURES / "synthetic_all_rules_good.tf")}
    assert not fired & AZURE_RULES
