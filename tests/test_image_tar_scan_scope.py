"""``agent-bom image --tar`` reports the image only, never the host's agents.

An image reference already skipped ambient MCP discovery, but an image
tarball did not: the laptop's Claude/Cursor agents were merged into an
image-only report whose ``scan_sources`` still said ``["image"]``.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

from agent_bom.models import Agent, AgentType, MCPServer


def _image_tar(tmp_path: Path) -> Path:
    content = b"Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.13.dfsg-1\nArchitecture: amd64\n\n"
    layer_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_buffer, mode="w:") as layer:
        member = tarfile.TarInfo("var/lib/dpkg/status")
        member.size = len(content)
        layer.addfile(member, io.BytesIO(content))
    layer_path = "0" * 40 + "/layer.tar"
    manifest = json.dumps([{"Config": "config.json", "RepoTags": ["scope:test"], "Layers": [layer_path]}]).encode()
    image_path = tmp_path / "image.tar"
    with tarfile.open(image_path, mode="w:") as image:
        layer_member = tarfile.TarInfo(layer_path)
        layer_member.size = len(layer_buffer.getvalue())
        image.addfile(layer_member, io.BytesIO(layer_buffer.getvalue()))
        manifest_member = tarfile.TarInfo("manifest.json")
        manifest_member.size = len(manifest)
        image.addfile(manifest_member, io.BytesIO(manifest))
    return image_path


def _host_agent() -> Agent:
    return Agent(
        name="laptop-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/home/user/.config/claude.json",
        mcp_servers=[MCPServer(name="laptop-server", command="npx", args=["-y", "laptop-server"])],
    )


def _discover(image_tars: tuple[str, ...], images: tuple[str, ...] = ()) -> tuple[list[Agent], list[dict[str, Any]]]:
    from rich.console import Console

    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._discovery import run_local_discovery
    from tests.test_discovery_characterization import BASE_KWARGS

    calls: list[dict[str, Any]] = []

    def _fake_discover(**kwargs: Any) -> list[Agent]:
        calls.append(kwargs)
        return [_host_agent()]

    ctx = ScanContext(con=Console(file=io.StringIO()))
    run_local_discovery(
        ctx,
        **{**BASE_KWARGS, "image_tars": image_tars, "images": images, "no_skill": True, "_image_only": True},
        _discover_all=_fake_discover,
    )
    return ctx.agents, calls


def test_image_tar_scan_does_not_run_host_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    agents, calls = _discover((str(_image_tar(tmp_path)),))

    assert calls == []
    assert "laptop-agent" not in [a.name for a in agents]
    assert agents, "the image tarball itself should still yield an agent"


def test_image_ref_scan_does_not_run_host_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom import image as image_mod
    from agent_bom.models import Package

    monkeypatch.setattr(image_mod, "scan_image", lambda ref, **_: ([Package(name="zlib", version="1.2.13", ecosystem="deb")], "fake"))
    monkeypatch.chdir(tmp_path)
    agents, calls = _discover((), images=("example.invalid/app:1",))

    assert calls == []
    assert "laptop-agent" not in [a.name for a in agents]
