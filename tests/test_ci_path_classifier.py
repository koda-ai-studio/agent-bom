"""Contracts for the fail-closed CI path classifier."""

from __future__ import annotations

from scripts.classify_ci_changes import classify_paths


def test_readme_and_documentation_changes_are_docs_only() -> None:
    result = classify_paths(
        [
            "README.md",
            "docs/operations/CI_RUNBOOK.md",
            "site-docs/getting-started.md",
            "mkdocs.yml",
        ]
    )

    assert result.docs_only is True
    assert result.changed_count == 4


def test_docs_only_allows_public_documentation_assets() -> None:
    result = classify_paths(
        [
            "docs/images/dashboard-light.png",
            "site-docs/assets/stylesheets/extra.css",
            ".github/ISSUE_TEMPLATE/bug_report.yml",
        ]
    )

    assert result.docs_only is True


def test_mixed_documentation_and_product_change_fails_closed() -> None:
    result = classify_paths(["README.md", "src/agent_bom/api/server.py"])

    assert result.docs_only is False


def test_workflow_dependency_and_ui_changes_are_not_docs_only() -> None:
    for path in (
        ".github/workflows/ci.yml",
        "pyproject.toml",
        "uv.lock",
        "ui/app/page.tsx",
        "deploy/helm/agent-bom/values.yaml",
    ):
        assert classify_paths([path]).docs_only is False, path


def test_empty_or_malformed_path_input_fails_closed() -> None:
    assert classify_paths([]).docs_only is False
    assert classify_paths(["", "../README.md"]).docs_only is False


def test_source_edits_do_not_change_frozen_python_dependency_inputs() -> None:
    for path in ["README.md", "docs/images/graph.png", "ui/app/page.tsx"]:
        result = classify_paths([path])
        assert result.python_dependencies is False
    assert classify_paths(["src/agent_bom/output/sarif.py"]).python_dependencies is False


def test_dependency_routing_includes_lockfiles_packaging_and_install_tooling() -> None:
    for path in [
        "uv.lock",
        "pyproject.toml",
        "setup.py",
        ".clusterfuzzlite/requirements.txt",
        "requirements/test.in",
        "constraints-prod.txt",
        ".python-version",
        ".github/actions/setup-python/action.yml",
        ".github/workflows/pr-security-gate.yml",
        "scripts/classify_ci_changes.py",
    ]:
        result = classify_paths([path])
        assert result.python_dependencies is True, path


def test_security_routing_fails_closed_on_unknown_or_ambiguous_paths() -> None:
    for paths in [[], ["../README.md"], ["README.md", ""], ["new-surface/unknown.data"]]:
        result = classify_paths(paths)
        assert result.python_dependencies is True


def test_registry_front_doors_and_fuzz_harnesses_route_to_their_lanes() -> None:
    registry = classify_paths(["docs/registry/PYPI_README.md", "docs/registry/DOCKER_HUB_README.md"])
    assert registry.docs_only is True

    fuzz = classify_paths([".clusterfuzzlite/fuzz/fuzz_policy.py"])
    assert fuzz.docs_only is False
    assert fuzz.python_dependencies is False


def test_correctness_routing_keeps_ordinary_docs_and_ui_prs_small() -> None:
    for path in ("README.md", "ui/app/page.tsx", "docs/images/graph.png", "tests/test_ci_path_classifier.py"):
        result = classify_paths([path])
        assert result.full_python is False, path
        assert result.postgres_required is False, path
        assert result.ui_container is False, path


def test_shared_inputs_and_unknown_code_require_full_correctness() -> None:
    for path in (
        "uv.lock",
        "pyproject.toml",
        ".github/workflows/ci.yml",
        "tests/conftest.py",
        "tests/fixtures/new.json",
        "src/agent_bom/canonical_ids.py",
        "src/agent_bom/models.py",
        "src/agent_bom/api/auth.py",
        "src/agent_bom/db/graph_store.py",
        "src/agent_bom/graph/not_yet_mapped.py",
        "new-surface/unknown.data",
    ):
        assert classify_paths([path]).full_python is True, path
    assert classify_paths([]).full_python is True


def test_mapped_source_uses_domain_tests_but_unmapped_sibling_fails_closed() -> None:
    assert classify_paths(["src/agent_bom/graph/builder.py"]).full_python is False
    assert classify_paths(["src/agent_bom/graph/builder.py", "src/agent_bom/graph/not_yet_mapped.py"]).full_python is True


def test_postgres_routing_covers_shared_identity_storage_and_auth_contracts() -> None:
    for path in (
        "src/agent_bom/models.py",
        "src/agent_bom/canonical_ids.py",
        "src/agent_bom/api/middleware.py",
        "src/agent_bom/db/graph_store.py",
        "tests/test_postgres_graph_store.py",
        "uv.lock",
    ):
        assert classify_paths([path]).postgres_required is True, path


def test_container_routing_covers_build_and_runtime_inputs() -> None:
    for path in (
        "ui/Dockerfile",
        "ui/docker-entrypoint.sh",
        "ui/package-lock.json",
        "ui/next.config.ts",
        "ui/.dockerignore",
        ".github/actions/setup-ui/action.yml",
        ".github/workflows/ci.yml",
    ):
        assert classify_paths([path]).ui_container is True, path


def test_version_only_metadata_uses_light_dependency_routing(tmp_path) -> None:
    import os
    import shutil
    import subprocess
    from pathlib import Path

    import yaml

    from scripts.classify_ci_changes import version_only_paths

    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()

    git("init", "-q")
    root = Path(__file__).resolve().parents[1]
    (tmp_path / "scripts").mkdir()
    for script_name in ("classify_ci_changes.py", "pytest_ci_plan.py"):
        shutil.copyfile(root / "scripts" / script_name, tmp_path / "scripts" / script_name)
    project = '[project]\nname = "agent-bom"\nversion = "0.109.0"\ndependencies = ["click>=8"]\n'
    lock = (
        'version = 1\n[[package]]\nname = "agent-bom"\nversion = "0.109.0"\n'
        'source = { editable = "." }\n[[package]]\nname = "click"\nversion = "8.3.0"\n'
    )
    for name, data in [("pyproject.toml", project), ("uv.lock", lock)]:
        (tmp_path / name).write_text(data)
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    for name, data in [("pyproject.toml", project), ("uv.lock", lock)]:
        (tmp_path / name).write_text(data.replace("0.109.0", "0.110.0"))
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "version")
    head = git("rev-parse", "HEAD")
    proven = version_only_paths(base, head, root=tmp_path)
    assert proven == {"pyproject.toml", "uv.lock"}
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    script = next(step["run"] for step in workflow["jobs"]["changes"]["steps"] if step.get("id") == "classify")
    for token, value in (
        ("github.event_name", "pull_request"),
        ("github.event.pull_request.base.sha", base),
        ("github.event.pull_request.head.sha", head),
    ):
        script = script.replace("${{ " + token + " }}", value)
    output = tmp_path / "outputs"
    env = {**os.environ, "GITHUB_SHA": head, "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")}
    run = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    for key in ("full_python", "alpine_full", "native_image", "endpoint", "postgres"):
        assert values[key] == "false", (key, values)
    assert values["python"] == "true"
    assert values["docs_only"] == "false"
    # Do not accidentally commit workflow output in subsequent fixture edits.
    output.unlink()
    (tmp_path / "summary").unlink()
    result = classify_paths(["pyproject.toml", "uv.lock"], version_only=proven)
    assert not result.docs_only  # wheel/import/version checks still apply
    assert not result.python_dependencies
    assert not result.full_python
    assert not result.postgres_required
    assert classify_paths(["pyproject.toml", "uv.lock", "src/agent_bom/models.py"], version_only=proven).full_python
    assert classify_paths(["pyproject.toml", "unknown.data"], version_only=proven).python_dependencies
    assert version_only_paths("missing-ref", head, root=tmp_path) == set()

    # A simultaneous dependency edit, resolver setting or malformed document
    # invalidates the exemption for that file.
    for name, content in [
        ("pyproject.toml", project.replace("0.109.0", "0.110.0").replace("click>=8", "click>=9")),
        ("pyproject.toml", project.replace("0.109.0", "0.110.0") + '\n[build-system]\nrequires = ["new-builder"]\n'),
        ("uv.lock", lock.replace("0.109.0", "0.110.0").replace("8.3.0", "8.4.0")),
        ("uv.lock", lock.replace("0.109.0", "0.110.0").replace("version = 1", "version = 2")),
        ("uv.lock", "invalid toml ["),
    ]:
        git("checkout", head, "--", "pyproject.toml", "uv.lock")
        (tmp_path / name).write_text(content)
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "mixed")
        exemptions = version_only_paths(base, git("rev-parse", "HEAD"), root=tmp_path)
        assert name not in exemptions
        assert classify_paths([name], version_only=exemptions).python_dependencies
