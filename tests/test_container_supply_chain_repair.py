from __future__ import annotations

import importlib.util
import json
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]


def test_every_published_python_image_removes_runtime_packaging_tools() -> None:
    """Build tooling and pip's vendored libraries must not ship at runtime.

    Pip 26.2's bundled SBOM includes vulnerable msgpack 1.1.2 and setuptools
    70.3.0 even though agent-bom does not import either package.  Removing pip,
    setuptools, and wheel from the final stage both shrinks the attack surface
    and keeps image scanners aligned with the executable runtime filesystem.
    """
    dockerfiles = [
        ROOT / "Dockerfile",
        ROOT / "deploy/docker/Dockerfile.collector",
        ROOT / "deploy/docker/Dockerfile.mcp",
        ROOT / "deploy/docker/Dockerfile.runtime",
        ROOT / "deploy/docker/Dockerfile.snowpark",
        ROOT / "deploy/docker/Dockerfile.sse",
        ROOT / "integrations/glama/Dockerfile",
    ]
    for dockerfile in dockerfiles:
        text = dockerfile.read_text(encoding="utf-8")
        assert "python -m pip uninstall --yes setuptools wheel pip" in text, dockerfile
        assert "deploy/docker/pip-requirements.txt" not in text, dockerfile

    assert not (ROOT / "deploy/docker/pip-requirements.txt").exists()


def test_all_direct_cryptography_constraints_exclude_cve_2026_69247() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    constraints: list[str] = []
    for requirement in project["dependencies"]:
        if Requirement(requirement).name.lower() == "cryptography":
            constraints.append(requirement)
    for requirements in project["optional-dependencies"].values():
        for requirement in requirements:
            if Requirement(requirement).name.lower() == "cryptography":
                constraints.append(requirement)
    assert constraints
    assert all("50.0.0" in Requirement(item).specifier for item in constraints)


def test_floating_latest_uses_reviewed_runtime_security_overlay() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/refresh-latest-container.yml").read_text(encoding="utf-8")
    requirements = (ROOT / "deploy/docker/runtime-security-requirements.txt").read_text(encoding="utf-8")

    assert "runtime-security-requirements.txt" in dockerfile
    assert "--no-config --python /app/.venv/bin/python --no-deps --require-hashes" in dockerfile
    assert "Dockerfile \\" in workflow
    assert "deploy/docker/runtime-security-requirements.txt \\" in workflow
    assert "cryptography==50.0.0" in requirements
    crypto_entry = next(entry for entry in requirements.replace("\\\n", "").splitlines() if entry.startswith("cryptography=="))
    assert crypto_entry.count("--hash=sha256:") == 2


@pytest.mark.parametrize("manifest", ["runtime-security-requirements.txt", "collector-security-requirements.txt"])
def test_release_refresh_replaces_vulnerable_certifi_with_hashed_universal_wheel(manifest: str) -> None:
    """The released lock stays frozen, so main's dependency floor is insufficient."""
    overlay = (ROOT / "deploy/docker" / manifest).read_text(encoding="utf-8")
    entries = overlay.replace("\\\n", "").splitlines()
    certifi_entry = next((entry for entry in entries if entry.startswith("certifi==")), "")
    assert certifi_entry, "release refresh must replace certifi from the old release lock"
    requirement = Requirement(certifi_entry.split("--hash=")[0].strip())
    assert "2026.7.22" not in requirement.specifier
    assert "2026.10.19" in requirement.specifier
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    package = next(package for package in lock["package"] if package["name"] == "certifi")
    assert package["version"] in requirement.specifier
    wheel = next(wheel for wheel in package["wheels"] if wheel["url"].endswith("-py3-none-any.whl"))
    assert f"--hash={wheel['hash']}" in certifi_entry


@pytest.mark.parametrize("manifest", ["runtime-security-requirements.txt", "collector-security-requirements.txt"])
def test_release_refresh_replaces_pyasn1_with_hashed_fixed_wheel(manifest: str) -> None:
    """Released locks retain 0.6.4 even after main moves to the patched decoder."""
    overlay = (ROOT / "deploy/docker" / manifest).read_text(encoding="utf-8")
    entries = overlay.replace("\\\n", "").splitlines()
    entry = next((entry for entry in entries if entry.startswith("pyasn1==")), "")
    assert entry, "release refresh must replace pyasn1 from the old release lock"
    requirement = Requirement(entry.split("--hash=")[0].strip())
    assert "0.6.4" not in requirement.specifier
    assert "0.6.5" in requirement.specifier
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    package = next(package for package in lock["package"] if package["name"] == "pyasn1")
    assert package["version"] in requirement.specifier
    wheel = next(wheel for wheel in package["wheels"] if wheel["url"].endswith("-py3-none-any.whl"))
    assert f"--hash={wheel['hash']}" in entry


def _refresh_step(job: str, name: str) -> tuple[int, dict]:
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/refresh-latest-container.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"][job]["steps"]
    for index, step in enumerate(steps):
        if step.get("name") == name:
            return index, step
    raise AssertionError(f"refresh job {job!r} has no step named {name!r}")


@pytest.mark.parametrize(
    ("job", "dockerfile_rel", "next_step"),
    [
        ("refresh-latest", "Dockerfile", "Sync Docker Hub README"),
        ("refresh-collector-latest", "deploy/docker/Dockerfile.collector", "Build refresh candidate collector image"),
    ],
)
def test_runtime_overlay_keeps_the_rebuilt_tag_version(tmp_path: Path, job: str, dockerfile_rel: str, next_step: str) -> None:
    """main's Dockerfile carries the NEXT version; the refreshed image is still the tag's release.

    Without re-pinning ARG VERSION the image was labelled with an unreleased
    version and the README-sync consistency check failed every day.
    """
    import os
    import subprocess

    overlay_index, overlay = _refresh_step(job, "Apply current runtime security overlay")
    pin_index, pin = _refresh_step(job, "Keep the rebuilt release version on the overlaid Dockerfile")
    next_index, _ = _refresh_step(job, next_step)
    assert overlay_index < pin_index < next_index
    assert pin["env"]["DOCKERFILE"] == dockerfile_rel
    assert dockerfile_rel in overlay["run"]

    dockerfile = tmp_path / dockerfile_rel
    dockerfile.parent.mkdir(parents=True, exist_ok=True)
    dockerfile.write_text('FROM scratch\nARG VERSION=0.106.0\nLABEL org.opencontainers.image.version="${VERSION}"\n')
    env = {**os.environ, "VERSION": "0.105.0", "DOCKERFILE": dockerfile_rel}
    result = subprocess.run(["bash", "-c", pin["run"]], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    text = dockerfile.read_text()
    assert "ARG VERSION=0.105.0\n" in text
    assert "0.106.0" not in text

    dockerfile.write_text("FROM scratch\n")
    missing = subprocess.run(["bash", "-c", pin["run"]], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)
    assert missing.returncode != 0, "a Dockerfile without ARG VERSION must fail loudly, not publish an unlabelled image"


def test_container_sarif_normalization_preserves_image_reference(tmp_path: Path) -> None:
    script_path = ROOT / "scripts/normalize_container_sarif_for_github.py"
    spec = importlib.util.spec_from_file_location("normalize_container_sarif_for_github", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    document = {
        "runs": [
            {
                "automationDetails": {"id": "agent-bom/scan"},
                "results": [
                    {
                        "ruleId": "CVE-2026-69247",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "docker://agentbom/agent-bom:latest"}}}],
                        "relatedLocations": [
                            {
                                "id": 0,
                                "logicalLocations": [{"fullyQualifiedName": "package:pip@26.1.2", "kind": "package"}],
                                "message": {"text": "pip@26.1.2"},
                            }
                        ],
                    }
                ],
            }
        ]
    }
    path = tmp_path / "image.sarif"
    path.write_text(json.dumps(document), encoding="utf-8")

    assert module.main([str(path)]) == 0
    normalized = json.loads(path.read_text(encoding="utf-8"))
    run = normalized["runs"][0]
    result = run["results"][0]
    artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "automationDetails" not in run
    assert artifact == {"uri": "Dockerfile", "uriBaseId": "%SRCROOT%"}
    assert result["properties"]["agent-bom:container_uri"] == "docker://agentbom/agent-bom:latest"
    related_physical = result["relatedLocations"][0]["physicalLocation"]
    assert related_physical == {"artifactLocation": {"uri": "Dockerfile", "uriBaseId": "%SRCROOT%"}}


def test_container_rescan_normalizes_sarif_without_making_upload_gating() -> None:
    workflow = (ROOT / ".github/workflows/container-rescan.yml").read_text(encoding="utf-8")
    assert "Normalize container SARIF for GitHub" in workflow
    assert "scripts/normalize_container_sarif_for_github.py" in workflow
    upload = workflow.split("- name: Upload SARIF to GitHub Security tab", 1)[1]
    assert "continue-on-error: true" in upload.split("- name:", 1)[0]


def test_container_rescan_runs_after_release_and_records_immutable_image_evidence() -> None:
    workflow = (ROOT / ".github/workflows/container-rescan.yml").read_text(encoding="utf-8")
    assert 'workflows: ["Release", "Refresh Docker Latest"]' in workflow
    assert "github.event.workflow_run.conclusion == 'success'" in workflow
    assert "Resolve pulled image identity" in workflow
    assert "IMAGE_ID:" in workflow
    assert "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" in workflow
    assert 'elif [ "${{ steps.triage.outputs.status }}" = "clean" ] && [ -n "$EXISTING" ]; then' in workflow
    assert "latest rescan was inconclusive, so this finding remains open" in workflow


def test_collector_refresh_applies_certifi_overlay_after_released_lock() -> None:
    dockerfile = (ROOT / "deploy/docker/Dockerfile.collector").read_text(encoding="utf-8")
    manifest = "deploy/docker/collector-security-requirements.txt"
    assert f"COPY {manifest} ./{manifest}" in dockerfile
    lock_install = dockerfile.index("uv sync --locked --no-dev --no-editable")
    security_install = dockerfile.index("uv pip install --no-config --python /app/.venv/bin/python --no-deps --require-hashes")
    assert lock_install < security_install < dockerfile.index("## ── Runtime stage")
    assert f"-r {manifest}" in dockerfile
    _, overlay = _refresh_step("refresh-collector-latest", "Apply current runtime security overlay")
    assert manifest in overlay["run"], "refresh must load current manifest after checking out the old release"
    requirements = (ROOT / manifest).read_text(encoding="utf-8")
    entries = [line for line in requirements.replace("\\\n", "").splitlines() if line and not line.startswith("#")]
    names = sorted(entry.split("==", 1)[0] for entry in entries)
    assert names == ["certifi", "filelock", "pyasn1"], "collector overlay is limited to universal pure-Python wheels"
    assert all("--hash=sha256:" in entry for entry in entries)


@pytest.mark.parametrize("dockerfile_path", ["Dockerfile", "deploy/docker/Dockerfile.collector"])
@pytest.mark.parametrize(("installed", "installer_status"), [(False, 0), (True, 0), (True, 23)])
def test_release_refresh_patches_tornado_only_when_present(
    tmp_path: Path, installed: bool, installer_status: int, dockerfile_path: str
) -> None:
    """Old release locks need the patch; new images must not regain an unused server."""
    import os
    import subprocess
    import sys

    dockerfile = (ROOT / dockerfile_path).read_text()
    marker = "if /app/.venv/bin/python -c"
    assert marker in dockerfile, "released Tornado 6.5.10 needs a conditional security overlay"
    command = dockerfile[dockerfile.index(marker) :].split("\n\n", 1)[0].replace("\\\n", "")
    command = command.replace("/app/.venv/bin/python", f'"{sys.executable}" -S')
    fake_uv = tmp_path / "uv"
    fake_uv.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "$RECEIPT"\nexit {installer_status}\n')
    fake_uv.chmod(0o755)
    if installed:
        (tmp_path / "tornado.py").write_text("# fixture module\n")
    receipt = tmp_path / "receipt"
    result = subprocess.run(
        ["sh", "-c", command],
        cwd=tmp_path,
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "PYTHONPATH": str(tmp_path), "RECEIPT": str(receipt)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == (installer_status if installed else 0), result.stderr
    assert receipt.exists() == installed
    if installed:
        args = receipt.read_text().splitlines()
        assert "--require-hashes" in args
        assert "--no-deps" in args
        assert "--only-binary=:all:" in args
        assert args[-2:] == ["-r", "deploy/docker/tornado-security-requirements.txt"]


@pytest.mark.parametrize(
    ("job", "dockerfile_path"), [("refresh-latest", "Dockerfile"), ("refresh-collector-latest", "deploy/docker/Dockerfile.collector")]
)
def test_tornado_refresh_manifest_is_hashed_and_reaches_released_build(job: str, dockerfile_path: str) -> None:
    manifest = "deploy/docker/tornado-security-requirements.txt"
    path = ROOT / manifest
    assert path.exists(), "old release locks need reviewed Tornado 6.6 wheels"
    entries = [line for line in path.read_text().replace("\\\n", "").splitlines() if line and not line.startswith("#")]
    assert len(entries) == 1
    requirement = Requirement(entries[0].split("--hash=")[0].strip())
    assert requirement.name == "tornado"
    assert "6.5.10" not in requirement.specifier
    assert str(requirement.specifier) == "==6.6"
    assert entries[0].count("--hash=sha256:") == 4
    assert f"COPY {manifest} ./{manifest}" in (ROOT / dockerfile_path).read_text()
    _, overlay = _refresh_step(job, "Apply current runtime security overlay")
    assert manifest in overlay["run"]
    # The ordinary package remains free of the obsolete web server dependency.
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert "tornado" not in {Requirement(item).name.lower() for item in project["dependencies"]}


@pytest.mark.parametrize("job", ["refresh-latest", "refresh-ui-latest", "refresh-collector-latest"])
def test_refresh_gate_retains_sarif_even_when_the_verdict_fails(job: str) -> None:
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/refresh-latest-container.yml").read_text())
    steps = workflow["jobs"][job]["steps"]
    gate_index = next(i for i, step in enumerate(steps) if "vulnerability refresh gate" in step.get("name", ""))
    gate = steps[gate_index]
    assert "--format sarif" in gate["run"]
    assert "--output image-refresh.sarif" in gate["run"]
    assert "--fail-on-severity medium" in gate["run"]
    assert "continue-on-error" not in gate
    assert "|| true" not in gate["run"]
    receipt = steps[gate_index + 1]
    assert receipt["if"] == "always()"
    assert receipt["uses"].startswith("actions/upload-artifact@")
    assert receipt["with"]["path"] == "image-refresh.sarif"
    assert receipt["with"]["name"] == f"{job}-scan-evidence"
