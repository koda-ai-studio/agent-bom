"""ATT&CK techniques on Docker, Compose and daemon IaC rules match what each rule detects."""

from __future__ import annotations

import pytest

from agent_bom.iac.attack_mapping import IAC_ATTACK_MAP, get_attack_techniques
from agent_bom.mitre_attack import get_bundled_attack_techniques


@pytest.mark.parametrize(
    ("rule_id", "techniques"),
    [
        ("DOCKER-001", ["T1525"]),  # mutable :latest base image
        ("DOCKER-002", ["T1611"]),  # runs as root
        ("DOCKER-005", ["T1105"]),  # curl | sh
        ("DOCKER-008", ["T1021.004"]),  # SSH exposed
        ("DOCKER-010", ["T1525"]),  # base not pinned by digest
        ("DOCKER-014", ["T1548.003"]),  # sudo
        ("DOCKER-022", ["T1105"]),  # ADD <url>
        ("DOCKER-026", ["T1552.001", "T1552.004"]),  # credential file in image
        ("COMPOSE-002", ["T1611", "T1610"]),  # docker.sock
        ("COMPOSE-011", ["T1548.001"]),  # setuid escalation allowed
        ("DOCKERD-001", ["T1133", "T1610"]),  # unauthenticated remote API
    ],
)
def test_docker_rules_map_to_the_technique_they_enable(rule_id: str, techniques: list[str]) -> None:
    assert get_attack_techniques(rule_id) == techniques


@pytest.mark.parametrize("rule_id", ["DOCKER-006", "DOCKER-007"])
def test_hygiene_rules_claim_no_technique(rule_id: str) -> None:
    assert get_attack_techniques(rule_id) == []


def test_every_mapped_technique_is_in_the_bundled_catalog() -> None:
    catalog = set(get_bundled_attack_techniques())
    unknown = sorted({t for techniques in IAC_ATTACK_MAP.values() for t in techniques} - catalog)
    assert not unknown
