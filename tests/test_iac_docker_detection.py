"""Which files the IaC walk treats as Dockerfiles."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac import is_iac_file, scan_iac_with_context

_DOCKERFILE = "FROM alpine:3.20\nRUN chmod 777 /srv\n"


@pytest.mark.parametrize("name", ["Dockerfile", "dockerfile", "Dockerfile.prod", "api.Dockerfile", "web.dockerfile", "Containerfile"])
def test_dockerfile_names_are_scanned(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text(_DOCKERFILE)
    result = scan_iac_with_context(tmp_path)
    assert {f.rule_id for f in result.findings} >= {"DOCKER-012"}
    assert next(v for v in result.verdicts if v.scanner_id == "dockerfile").files_scanned == 1


@pytest.mark.parametrize("name", ["Dockerfile.md", "Dockerfile.txt", "dockerfile_rules.py", "dockerfile-lint.js", "Dockerfile.yaml"])
def test_docs_and_code_named_like_dockerfiles_are_not_scanned(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    path.write_text(_DOCKERFILE)
    assert not any(f.category == "dockerfile" for f in scan_iac_with_context(tmp_path).findings)
    assert is_iac_file(path) is False


def test_file_without_from_is_not_reported_as_a_dockerfile(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("# placeholder, the real one is generated\n")
    assert scan_iac_with_context(tmp_path).findings == []
