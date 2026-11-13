"""The MCP server images are built, started and checked before they merge and before they publish."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
MCP_DOCKERFILES = {
    "mcp": "deploy/docker/Dockerfile.mcp",
    "sse": "deploy/docker/Dockerfile.sse",
    "public-mcp": "deploy/docker/Dockerfile.public-mcp",
}


def _workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _smoke() -> ModuleType:
    spec = importlib.util.spec_from_file_location("smoke_mcp_image", ROOT / "scripts" / "smoke_mcp_image.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["smoke_mcp_image"] = module
    spec.loader.exec_module(module)
    return module


def _matrix(job: dict) -> dict[str, dict]:
    return {entry["image"]: entry for entry in job["strategy"]["matrix"]["include"]}


# ── smoke script ────────────────────────────────────────────────────────────


def test_check_tools_accepts_a_healthy_server() -> None:
    mod = _smoke()
    assert mod.check_tools({"name": "agent-bom"}, ["check", "intel_lookup"], min_tools=1, expect=["intel_lookup", "check"]) == []


def test_check_tools_rejects_a_wrong_server_too_few_tools_or_a_forbidden_tool() -> None:
    mod = _smoke()
    assert mod.check_tools({"name": "other"}, ["scan"], min_tools=1, expect=[])
    assert mod.check_tools({"name": "agent-bom"}, ["scan"], min_tools=8, expect=[])
    assert mod.check_tools({"name": "agent-bom"}, ["check", "scan"], min_tools=1, expect=["check"])
    problems = mod.check_tools({"name": "agent-bom"}, ["scan", "agent_activity"], min_tools=1, expect=[])
    assert any("agent_activity" in problem for problem in problems)


def test_streamable_http_bodies_parse_as_json_or_a_single_sse_event() -> None:
    mod = _smoke()
    assert mod._sse_json('{"jsonrpc":"2.0","id":1,"result":{}}')["id"] == 1
    assert mod._sse_json('event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n\n')["id"] == 2


# ── pre-merge CI ────────────────────────────────────────────────────────────


def test_ci_builds_and_smokes_all_three_mcp_images() -> None:
    jobs = _workflow("ci.yml")["jobs"]
    job = jobs["mcp-images"]
    assert job["permissions"] == {"contents": "read"}
    assert "!cancelled()" in job["if"] and "always()" not in job["if"]
    assert "needs.changes.result != 'success'" in job["if"], "fails closed when the classifier fails"
    assert "needs.changes.outputs.mcp_images == 'true'" in job["if"]
    matrix = _matrix(job)
    assert {name: entry["dockerfile"] for name, entry in matrix.items()} == MCP_DOCKERFILES
    assert "--transport stdio" in matrix["mcp"]["smoke"]
    assert "--transport http --bearer" in matrix["sse"]["smoke"]
    assert "--transport http" in matrix["public-mcp"]["smoke"] and "--expect-tools check,intel_lookup" in matrix["public-mcp"]["smoke"]
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert 'docker build -f "$DOCKERFILE"' in runs
    assert "scripts/smoke_mcp_image.py" in runs
    # The hosted images sync the advisory database before serving.
    assert job["timeout-minutes"] >= 20


def test_mcp_image_classifier_covers_dockerfiles_sources_and_the_smoke() -> None:
    run = next(step["run"] for step in _workflow("ci.yml")["jobs"]["changes"]["steps"] if step.get("id") == "classify")
    lines = run.splitlines()
    condition = lines[next(i for i, line in enumerate(lines) if line.strip() == "mcp_images=true") - 1]
    assert '"$dependency_changed"' in condition
    regex = re.compile(re.search(r"grep -E '([^']+)'", condition).group(1))
    for path in (
        "deploy/docker/Dockerfile.mcp",
        "deploy/docker/Dockerfile.sse",
        "deploy/docker/Dockerfile.public-mcp",
        "src/agent_bom/mcp_server.py",
        "src/agent_bom/mcp_tools/registry.py",
        "src/agent_bom/cli/_server.py",
        "scripts/smoke_mcp_image.py",
        "uv.lock",
        ".github/workflows/publish-mcp.yml",
    ):
        assert regex.search(path), path
    assert not regex.search("deploy/docker/Dockerfile.collector")
    outputs = _workflow("ci.yml")["jobs"]["changes"]["outputs"]
    assert outputs["mcp_images"] == "${{ steps.classify.outputs.mcp_images }}"
    assert 'echo "mcp_images=${mcp_images}"' in run


def test_required_test_context_includes_the_mcp_image_lane() -> None:
    job = _workflow("ci.yml")["jobs"]["test"]
    assert "mcp-images" in job["needs"]
    step = job["steps"][0]
    assert step["env"]["MCP_IMAGES_RESULT"] == "${{ needs.mcp-images.result }}"
    assert "MCP_IMAGES_REQUIRED" in step["env"]
    assert "for lane in ALPINE UI_E2E MCP_IMAGES; do" in step["run"]


# ── publish ─────────────────────────────────────────────────────────────────


def test_publish_gates_each_image_before_any_push() -> None:
    jobs = _workflow("publish-mcp.yml")["jobs"]
    gate = jobs["gate"]
    assert gate["permissions"] == {"contents": "read"}, "the gate builds release code, so it holds no write token"
    assert gate["needs"] == "release"
    matrix = _matrix(gate)
    assert {name: entry["dockerfile"] for name, entry in matrix.items()} == {k: MCP_DOCKERFILES[k] for k in ("mcp", "sse")}
    # The release source stays inside BuildKit; the runner checks out and runs only
    # default-branch code, so no release code can write to the default branch's cache.
    checkouts = [step for step in gate["steps"] if step.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1
    assert checkouts[0]["with"]["ref"] == "${{ github.event.repository.default_branch }}"
    assert checkouts[0]["with"]["persist-credentials"] is False
    build = next(step for step in gate["steps"] if step.get("name") == "Build candidate image")
    assert build["env"]["CONTEXT"] == "https://github.com/${{ github.repository }}.git#${{ needs.release.outputs.release_sha }}"
    assert '"$CONTEXT"' in build["run"]
    runs = "\n".join(step.get("run", "") for step in gate["steps"])
    assert "scripts/smoke_mcp_image.py" in runs
    # Same policy as the release container gate: the image scans a saved tar of itself.
    assert "image --tar /scan/image.tar" in runs
    assert "--ignore /scan/.image-scan-ignore" in runs
    assert "--exclude-unfixable" in runs
    assert "--fail-on-severity medium" in runs
    for publisher in ("publish-stdio", "publish-sse"):
        assert set(jobs[publisher]["needs"]) == {"release", "gate"}, publisher
