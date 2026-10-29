"""Keep CI and publication on the same compatible docs renderer."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_docs_builds_share_the_compatible_highlighter_pin():
    commands = []
    for name in ("ci.yml", "docs-build.yml"):
        workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
        commands.extend(
            step["run"]
            for job in workflow["jobs"].values()
            for step in job.get("steps", [])
            if step.get("run", "").startswith("uv tool run") and "mkdocs build --strict" in step["run"]
        )
    assert len(commands) == 2
    assert commands[0] == commands[1]
    # mkdocstrings 1.0.3 uses the pre-12 Highlight constructor.
    assert "--with pymdown-extensions==11.0.2" in commands[0]


def test_release_calls_the_docs_build_without_a_deploy_job():
    """The release summary must not show a skipped Pages deploy on every tag."""
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    docs_job = release["jobs"]["docs-site"]
    assert docs_job["uses"] == "./.github/workflows/docs-build.yml"
    assert "with" not in docs_job
    assert docs_job["permissions"] == {"contents": "read"}

    build = yaml.safe_load((ROOT / ".github/workflows/docs-build.yml").read_text())
    assert list(build["jobs"]) == ["build"]
    assert build.get(True, build.get("on")) == {"workflow_call": None}

    docs = yaml.safe_load((ROOT / ".github/workflows/docs.yml").read_text())
    assert docs["jobs"]["build"]["uses"] == "./.github/workflows/docs-build.yml"
    assert docs["jobs"]["deploy"]["needs"] == "build"
    assert "workflow_call" not in docs.get(True, docs.get("on"))
    assert ".github/workflows/docs-build.yml" in docs.get(True, docs.get("on"))["push"]["paths"]
