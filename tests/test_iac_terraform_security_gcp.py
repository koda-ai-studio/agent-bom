"""GCP Terraform misconfiguration rules (TF-SEC-2xx)."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from agent_bom.iac.terraform_security import scan_terraform_security

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "iac_golden" / "terraform"
GCP_RULES = {f"TF-SEC-{n}" for n in range(201, 212)}


def _rules(path: Path) -> Counter[str]:
    return Counter(f.rule_id for f in scan_terraform_security(path))


def _scan(tmp_path: Path, content: str) -> list:
    path = tmp_path / "main.tf"
    path.write_text(content)
    return scan_terraform_security(path)


def test_misconfigured_gcp_corpus_fires_every_gcp_rule() -> None:
    fired = _rules(FIXTURES / "synthetic_gcp_misconfig.tf")
    assert GCP_RULES <= set(fired), sorted(GCP_RULES - set(fired))
    assert fired["TF-SEC-201"] == 2  # allUsers member + allAuthenticatedUsers binding
    assert fired["TF-SEC-202"] == 2  # explicit false + provider default (false)
    assert fired["TF-SEC-203"] == 4  # ssh, rdp range via ::/0, all ports, other port
    assert fired["TF-SEC-208"] == 3  # two instances + project metadata


def test_clean_gcp_corpus_is_clean() -> None:
    assert _rules(FIXTURES / "synthetic_gcp_good.tf") == Counter()


def test_gcp_rules_carry_cis_gcp_ids_and_remediation() -> None:
    findings = [f for f in scan_terraform_security(FIXTURES / "synthetic_gcp_misconfig.tf") if f.rule_id in GCP_RULES]
    for finding in findings:
        assert finding.remediation, finding.rule_id
        assert not any(cid.startswith(("CIS-AWS-", "CIS-Azure-")) for cid in finding.compliance), finding.rule_id
        assert any(cid.startswith("NIST-") for cid in finding.compliance), finding.rule_id
    cis = {f.rule_id: sorted(c for c in f.compliance if c.startswith("CIS-GCP-")) for f in findings}
    assert cis["TF-SEC-201"] == ["CIS-GCP-5.1"]
    assert cis["TF-SEC-202"] == ["CIS-GCP-5.2"]
    assert cis["TF-SEC-204"] == ["CIS-GCP-6.2"]
    assert cis["TF-SEC-205"] == ["CIS-GCP-6.1"]
    assert cis["TF-SEC-206"] == ["CIS-GCP-6.3"]
    assert cis["TF-SEC-207"] == ["CIS-GCP-4.9"]
    assert cis["TF-SEC-208"] == ["CIS-GCP-4.4"]
    assert cis["TF-SEC-209"] == ["CIS-GCP-4.5"]
    assert cis["TF-SEC-210"] == ["CIS-GCP-3.9"]
    assert cis["TF-SEC-211"] == ["CIS-GCP-4.6"]


def test_firewall_rule_maps_ports_to_the_right_cis_controls(tmp_path: Path) -> None:
    def fw(allow: str, ranges: str = '["0.0.0.0/0"]') -> list:
        return [
            f
            for f in _scan(tmp_path, f'resource "google_compute_firewall" "r" {{\n  {allow}\n  source_ranges = {ranges}\n}}\n')
            if f.rule_id == "TF-SEC-203"
        ]

    ssh = fw('allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }')
    assert [f.severity for f in ssh] == ["critical"]
    assert "CIS-GCP-3.6" in ssh[0].compliance and "CIS-GCP-3.7" not in ssh[0].compliance
    rdp = fw('allow {\n    protocol = "tcp"\n    ports = ["3389"]\n  }')
    assert "CIS-GCP-3.7" in rdp[0].compliance
    everything = fw('allow {\n    protocol = "all"\n  }')
    assert {"CIS-GCP-3.6", "CIS-GCP-3.7"} <= set(everything[0].compliance)
    no_ports = fw('allow {\n    protocol = "tcp"\n  }')
    assert {"CIS-GCP-3.6", "CIS-GCP-3.7"} <= set(no_ports[0].compliance)
    other = fw('allow {\n    protocol = "tcp"\n    ports = ["9000"]\n  }')
    assert [f.severity for f in other] == ["high"]
    assert not any(c.startswith("CIS-GCP-") for c in other[0].compliance)
    assert fw('allow {\n    protocol = "tcp"\n    ports = ["80", "443"]\n  }') == []
    assert fw('allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }', '["10.0.0.0/8"]') == []
    assert fw('deny {\n    protocol = "all"\n  }') == []


def test_cloud_sql_public_ip_severity_depends_on_authorized_networks(tmp_path: Path) -> None:
    def sql(ip_config: str) -> list:
        return [
            f
            for f in _scan(
                tmp_path,
                'resource "google_sql_database_instance" "d" {\n  settings {\n    ip_configuration {\n' + ip_config + "    }\n  }\n}\n",
            )
            if f.rule_id == "TF-SEC-204"
        ]

    assert [f.severity for f in sql("      ipv4_enabled = true\n")] == ["high"]
    open_network = '      ipv4_enabled = true\n      authorized_networks {\n        value = "0.0.0.0/0"\n      }\n'
    assert [f.severity for f in sql(open_network)] == ["critical"]
    assert sql("      ipv4_enabled = false\n") == []
    assert sql("") == []  # no explicit public IP configured; not asserted


@pytest.mark.parametrize(
    ("snippet", "expected"),
    [
        ("      require_ssl = false\n", {"TF-SEC-205"}),
        ('      ssl_mode = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"\n', {"TF-SEC-205"}),
        ('      ssl_mode = "ENCRYPTED_ONLY"\n', set()),
        ("      require_ssl = true\n", set()),
        ("", set()),
    ],
)
def test_cloud_sql_ssl_enforcement(tmp_path: Path, snippet: str, expected: set[str]) -> None:
    content = 'resource "google_sql_database_instance" "d" {\n  settings {\n    ip_configuration {\n' + snippet + "    }\n"
    content += "    backup_configuration {\n      enabled = true\n    }\n  }\n}\n"
    assert {f.rule_id for f in _scan(tmp_path, content)} == expected


def test_cloud_sql_backups_missing_or_disabled(tmp_path: Path) -> None:
    missing = _scan(tmp_path, 'resource "google_sql_database_instance" "d" {\n  settings {\n    tier = "db-f1-micro"\n  }\n}\n')
    assert [f.rule_id for f in missing] == ["TF-SEC-206"]
    disabled = _scan(
        tmp_path,
        'resource "google_sql_database_instance" "d" {\n  settings {\n    backup_configuration {\n      enabled = false\n    }\n  }\n}\n',
    )
    assert [(f.rule_id, f.line_number) for f in disabled] == [("TF-SEC-206", 4)]


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        ('enable-oslogin = "false"', {"TF-SEC-208"}),
        ('"enable-oslogin" = "FALSE"', {"TF-SEC-208"}),
        ('enable-oslogin = "true"', set()),
        ('serial-port-enable = "true"', {"TF-SEC-209"}),
        ('serial-port-enable = "0"', set()),
        ("", set()),  # OS Login absence is a project-level posture question, not asserted per instance
    ],
)
def test_instance_metadata_flags(tmp_path: Path, metadata: str, expected: set[str]) -> None:
    content = f'resource "google_compute_instance" "vm" {{\n  metadata = {{\n    {metadata}\n  }}\n'
    content += '  network_interface {\n    network = "default"\n  }\n}\n'
    assert {f.rule_id for f in _scan(tmp_path, content)} == expected


def test_instance_public_ip_and_ip_forwarding(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'resource "google_compute_instance" "vm" {\n  can_ip_forward = true\n  network_interface {\n'
        '    network = "default"\n    access_config {\n      nat_ip = "203.0.113.5"\n    }\n  }\n}\n',
    )
    assert sorted(f.rule_id for f in findings) == ["TF-SEC-207", "TF-SEC-211"]
    assert all(f.severity == "medium" for f in findings)


def test_single_line_blocks_with_semicolons_are_parsed(tmp_path: Path) -> None:
    content = (
        'resource "google_compute_firewall" "ssh" {\n'
        '  allow { protocol = "tcp"; ports = ["22"] }\n'
        '  source_ranges = ["0.0.0.0/0"]\n'
        "}\n"
        'resource "google_sql_database_instance" "db" {\n'
        "  settings {\n"
        "    ip_configuration { ipv4_enabled = true; require_ssl = false\n"
        '      authorized_networks { value = "0.0.0.0/0" } }\n'
        "  }\n"
        "}\n"
    )
    fired = {(f.rule_id, f.severity) for f in _scan(tmp_path, content)}
    assert fired == {("TF-SEC-203", "critical"), ("TF-SEC-204", "critical"), ("TF-SEC-205", "high"), ("TF-SEC-206", "medium")}


def test_aws_rules_do_not_fire_on_gcp_resources() -> None:
    for name in ("synthetic_gcp_misconfig.tf", "synthetic_gcp_good.tf"):
        fired = {f.rule_id for f in scan_terraform_security(FIXTURES / name)}
        assert not {r for r in fired if r.startswith("TF-SEC-0") and r not in {"TF-SEC-007", "TF-SEC-051"}}, name
        assert not {r for r in fired if r.startswith("TF-SEC-1")}, name


def test_gcp_rules_do_not_fire_on_aws_resources() -> None:
    fired = {f.rule_id for f in scan_terraform_security(FIXTURES / "synthetic_all_rules_good.tf")}
    assert not fired & GCP_RULES
