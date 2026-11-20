"""Every image family the release docs promise is a monitored freshness surface."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _release_verification_images() -> set[str]:
    """Image repositories docs/RELEASE_VERIFICATION.md promises per release."""
    text = (ROOT / "docs" / "RELEASE_VERIFICATION.md").read_text()
    section = text.split("### 6. Docker Images", 1)[1].split("\n### ", 1)[0]
    images: set[str] = set()
    for line in section.splitlines():
        if line.startswith("| `"):
            images.update(re.findall(r"`((?:ghcr\.io/|agentbom/)[a-z0-9./-]+)`", line.split("|")[1]))
    return images


def test_every_documented_release_image_is_a_freshness_surface(monkeypatch, tmp_path):
    """A published image the release docs promise must not drift unmonitored.

    The MCP stdio and HTTP images sat two releases behind while the monitor
    reported every surface fresh, because only the API image was probed.
    """
    script = _load_script("check_surface_freshness.py")
    probed: dict[str, str] = {}

    def fresh(name):
        return lambda expected, *args, **kwargs: {"surface": name, "status": "fresh", "version": expected, "expected": expected}

    def fake_docker(expected, image, *, surface="Docker", **_kw):
        probed[image] = surface
        return {"surface": surface, "status": "fresh", "version": expected, "expected": expected}

    for name, attribute in (("PyPI", "probe_pypi"), ("MCP Registry", "probe_mcp_registry"), ("Glama", "probe_glama")):
        monkeypatch.setattr(script, attribute, fresh(name))
    monkeypatch.setattr(script, "probe_docker", fake_docker)

    out = tmp_path / "report.json"
    assert script.main(["--expected", "0.115.4", "--retired-smithery", "--out", str(out)]) == 0

    documented = _release_verification_images()
    assert {"ghcr.io/koda-ai-studio/agent-bom-mcp", "ghcr.io/koda-ai-studio/agent-bom-sse"} <= documented
    assert documented <= set(probed)
    assert len(set(probed.values())) == len(probed), "each image needs its own surface name in the report"
    report_surfaces = {surface["surface"] for surface in json.loads(out.read_text())["surfaces"]}
    assert set(probed.values()) <= report_surfaces


def test_stale_mcp_image_fails_the_freshness_gate(monkeypatch, tmp_path):
    script = _load_script("check_surface_freshness.py")

    def fresh(name):
        return lambda expected, *args, **kwargs: {"surface": name, "status": "fresh", "version": expected, "expected": expected}

    def tags_for(expected, image, *, surface="Docker", **_kw):
        published = "0.113.2" if image.endswith("-mcp") else expected
        return script._classify(surface, published, expected)

    for name, attribute in (("PyPI", "probe_pypi"), ("MCP Registry", "probe_mcp_registry"), ("Glama", "probe_glama")):
        monkeypatch.setattr(script, attribute, fresh(name))
    monkeypatch.setattr(script, "probe_docker", tags_for)

    out = tmp_path / "report.json"
    assert script.main(["--expected", "0.115.4", "--retired-smithery", "--fail-on-stale", "--out", str(out)]) == 1
    stale = [s for s in json.loads(out.read_text())["surfaces"] if s["status"] == "stale"]
    assert [(s["surface"], s["version"]) for s in stale] == [("MCP image (stdio)", "0.113.2")]


def test_docker_probe_names_its_surface(monkeypatch):
    script = _load_script("check_surface_freshness.py")
    monkeypatch.setattr(script, "_http_json", lambda url, **_kw: {"token": "t"})
    monkeypatch.setattr(script, "_http_json_response", lambda url, **_kw: ({"tags": ["v0.113.2", "latest"]}, {}))

    result = script.probe_docker(
        "0.115.4", "ghcr.io/koda-ai-studio/agent-bom-sse", surface="MCP image (HTTP)", timeout=1, attempts=1, backoff=0
    )

    assert result["surface"] == "MCP image (HTTP)"
    assert result["status"] == "stale"
    assert result["version"] == "0.113.2"
