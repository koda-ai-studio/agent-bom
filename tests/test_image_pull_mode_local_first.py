"""Auto pull mode scans the local image a short reference names before a same-named Docker Hub image."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

import pytest

from agent_bom.image import scan_image
from agent_bom.image_evidence import collect_image_evidence
from agent_bom.models import Package
from agent_bom.oci_registry import client as registry_client
from agent_bom.oci_registry.reference import DOCKER_HUB_API
from tests._oci_image_builder import build_image, dpkg_status
from tests._oci_registry_fake import REGISTRY, FakeRegistry


class FakeDaemon:
    """A Docker CLI whose image store holds ``inventory``; every other command fails."""

    def __init__(self, inventory: set[str]) -> None:
        self.inventory = inventory
        self.commands: list[list[str]] = []
        self.scanned: list[str] = []

    def run(self, cmd: list[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        self.commands.append(list(cmd))
        if cmd[:3] == ["docker", "image", "inspect"] and cmd[-1] in self.inventory:
            return subprocess.CompletedProcess(cmd, 0, stdout="sha256:" + "c" * 64 + "\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="No such image")

    def scan(self, ref: str, platform: str | None = None) -> list[Package]:
        self.scanned.append(ref)
        return [Package(name="local-only", version="1", ecosystem="deb")]


@pytest.fixture
def setup(monkeypatch):
    hub = FakeRegistry(host=DOCKER_HUB_API)
    hub.push_image("acme/app", build_image([{"var/lib/dpkg/status": dpkg_status(("squatted", "6.6.6"))}]), "dev")
    hub.push_image("team/app", build_image([{"var/lib/dpkg/status": dpkg_status(("remote", "1"))}]), "1.0")
    monkeypatch.setattr(registry_client, "_default_transport", hub.transport)
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    daemon = FakeDaemon({"acme/app:dev", f"{REGISTRY}/team/app:1.0"})
    monkeypatch.setattr("agent_bom.image.subprocess.run", daemon.run)
    monkeypatch.setattr("agent_bom.image._scan_with_docker", daemon.scan)
    monkeypatch.setattr("agent_bom.image._daemon_supply_chain", lambda *a: None)
    monkeypatch.delenv("AGENT_BOM_IMAGE_PULL_MODE", raising=False)
    return hub, daemon


def test_auto_mode_scans_the_local_image_for_a_reference_without_a_registry_host(setup):
    hub, daemon = setup

    with collect_image_evidence("acme/app:dev") as evidence:
        packages, strategy = scan_image("acme/app:dev")

    assert (strategy, [p.name for p in packages]) == ("native", ["local-only"])
    assert daemon.scanned == ["acme/app:dev"]
    assert hub.requests == [], "a short reference present locally must never resolve to Docker Hub"
    assert evidence.source == "daemon"
    assert any("local Docker image" in note for note in evidence.notes)


def test_auto_mode_pulls_from_the_registry_when_the_short_reference_is_not_local(setup):
    hub, daemon = setup

    packages, strategy = scan_image("team/app:1.0")

    assert (strategy, [p.name for p in packages]) == ("registry", ["remote"])
    assert daemon.scanned == []


def test_explicit_registry_host_keeps_registry_first_even_when_local(setup, monkeypatch):
    _hub, daemon = setup
    pulled: list[str] = []
    monkeypatch.setattr(
        "agent_bom.image.scan_registry_image",
        lambda ref, **_kw: pulled.append(ref) or [Package(name="remote", version="1", ecosystem="deb")],
    )

    _packages, strategy = scan_image(f"{REGISTRY}/team/app:1.0")

    assert strategy == "registry" and pulled == [f"{REGISTRY}/team/app:1.0"]
    assert daemon.scanned == []


def test_registry_mode_and_server_scans_never_consult_the_local_daemon(setup):
    hub, daemon = setup

    _packages, strategy = scan_image("acme/app:dev", pull_mode="registry")
    assert strategy == "registry"
    _packages, strategy = scan_image("acme/app:dev", server_context=True)
    assert strategy == "registry"
    assert daemon.scanned == []
    assert not [c for c in daemon.commands if c[:3] == ["docker", "image", "inspect"]]
