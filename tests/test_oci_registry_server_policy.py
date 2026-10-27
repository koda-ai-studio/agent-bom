"""Server-side image scans (API jobs, MCP) never turn a tenant reference into internal egress or ambient-credential use."""

from __future__ import annotations

import base64
import json
import shutil
import socket
from typing import Any

import pytest

from agent_bom.image import ImageScanError, scan_image
from agent_bom.image_evidence import collect_image_evidence
from agent_bom.models import Package
from agent_bom.oci_registry import client as registry_client
from agent_bom.oci_registry.client import RegistryClient, RegistryPolicyError
from agent_bom.oci_registry.policy import LOCAL_POLICY, RegistryPolicy
from agent_bom.oci_registry.reference import parse_reference
from agent_bom.scanners.state import reset_scan_warnings
from tests._oci_image_builder import build_image, dpkg_status
from tests._oci_registry_fake import REGISTRY, FakeRegistry

REF = f"{REGISTRY}/team/app:1.0"


@pytest.fixture
def registry(monkeypatch):
    fake = FakeRegistry()
    monkeypatch.setattr(registry_client, "_default_transport", fake.transport)
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    for name in ("AGENT_BOM_REGISTRY_USER", "AGENT_BOM_REGISTRY_PASS", "AGENT_BOM_REGISTRY_ALLOWLIST", "AGENT_BOM_IMAGE_PULL_MODE"):
        monkeypatch.delenv(name, raising=False)
    reset_scan_warnings()
    return fake


def _image(**kwargs: Any):
    return build_image([{"var/lib/dpkg/status": dpkg_status(("bash", "5.2.15"))}], **kwargs)


@pytest.mark.parametrize(
    "ref",
    [
        "localhost:5000/team/app:1",
        "localhost/team/app:1",
        "127.0.0.1:5000/team/app:1",
        "10.0.0.5:5000/team/app:1",
        "192.168.1.10/team/app:1",
        "100.64.0.1/team/app:1",
        "169.254.169.254/team/app:1",
        "metadata.google.internal/team/app:1",
    ],
)
def test_server_scan_refuses_loopback_private_cgnat_and_metadata_registries(registry, ref):
    with pytest.raises(ImageScanError, match="egress policy") as raised:
        scan_image(ref, server_context=True)

    assert registry.requests == []
    assert "HTTP" not in str(raised.value)


def test_server_scan_never_uses_plain_http_while_the_local_cli_keeps_loopback_http():
    local = RegistryClient(parse_reference("localhost:5000/team/app:1"))
    assert local.base_url.startswith("http://")
    local.close()
    assert RegistryPolicy(server=True).refusal(parse_reference("localhost:5000/team/app:1")) is not None


def test_server_scan_pins_dns_answers_at_connect_time(monkeypatch):
    seen: list[str] = []

    def private_answer(host, port, *args, **kwargs):
        seen.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port))]

    monkeypatch.setattr(socket, "getaddrinfo", private_answer)
    monkeypatch.setattr(registry_client, "_default_transport", lambda: None)  # the production transport, not the suite's stub
    ref = parse_reference("registry.internal.example.test/team/app:1")
    client = RegistryClient(ref, policy=RegistryPolicy(server=True))
    with pytest.raises(RegistryPolicyError, match="egress policy"):
        client.get_manifest("1")
    client.close()
    assert seen == ["registry.internal.example.test"]


def test_server_scan_never_uses_ambient_docker_config_or_environment_credentials(registry, tmp_path, monkeypatch):
    registry.auth = "token-basic"
    registry.push_image("team/app", _image(), "1.0")
    encoded = base64.b64encode(f"{registry.username}:{registry.password}".encode()).decode()
    (tmp_path / "config.json").write_text(json.dumps({"auths": {REGISTRY: {"auth": encoded}}}))
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_REGISTRY_USER", registry.username)
    monkeypatch.setenv("AGENT_BOM_REGISTRY_PASS", registry.password)

    with collect_image_evidence(REF), pytest.raises(ImageScanError) as raised:
        scan_image(REF, server_context=True)

    assert all("authorization" not in r.headers or not r.headers["authorization"].startswith("Basic") for r in registry.requests)
    assert "HTTP 401" not in str(raised.value)

    packages, strategy = scan_image(REF)  # the local CLI still uses the operator's own credentials
    assert (strategy, [p.name for p in packages]) == ("registry", ["bash"])


def test_server_scan_errors_withhold_upstream_status(registry):
    with pytest.raises(ImageScanError) as raised:
        scan_image(f"{REGISTRY}/team/missing:1", server_context=True)

    assert "404" not in str(raised.value) and "HTTP" not in str(raised.value)


def test_server_scan_honours_the_registry_allowlist(registry, monkeypatch):
    registry.push_image("team/app", _image(), "1.0")
    monkeypatch.setenv("AGENT_BOM_REGISTRY_ALLOWLIST", "allowed.example.test, other.example.test")

    with pytest.raises(ImageScanError, match="not in AGENT_BOM_REGISTRY_ALLOWLIST"):
        scan_image(REF, server_context=True)
    assert registry.requests == []

    monkeypatch.setenv("AGENT_BOM_REGISTRY_ALLOWLIST", REGISTRY)
    packages, strategy = scan_image(REF, server_context=True)
    assert (strategy, [p.name for p in packages]) == ("registry", ["bash"])


def test_server_scan_skips_a_base_image_label_pointing_at_another_registry(registry):
    digest = "sha256:" + "b" * 64
    labels = {"org.opencontainers.image.base.name": "attacker.example.test/base:1", "org.opencontainers.image.base.digest": digest}
    registry.push_image("team/app", _image(labels=labels), "1.0")

    with collect_image_evidence(REF) as evidence:
        packages, _ = scan_image(REF, server_context=True)

    assert [p.name for p in packages] == ["bash"]
    assert not [r for r in registry.requests if r.url.host == "attacker.example.test"]
    assert evidence.base_image is not None and evidence.base_image["attribution"] == "skipped-by-policy"


def test_local_scan_still_fetches_a_labelled_base_image(registry):
    labels = {"org.opencontainers.image.base.name": "attacker.example.test/base:1"}
    registry.push_image("team/app", _image(labels=labels), "1.0")

    with collect_image_evidence(REF) as evidence:
        scan_image(REF)

    assert evidence.base_image is not None
    assert [r for r in registry.requests if r.url.host == "attacker.example.test"]


def test_server_scan_never_falls_back_to_the_docker_daemon(registry, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    called: list[str] = []
    monkeypatch.setattr("agent_bom.image._scan_with_docker", lambda ref, platform=None: called.append(ref) or [Package(name="x", version="1", ecosystem="deb")])

    with pytest.raises(ImageScanError):
        scan_image(f"{REGISTRY}/team/missing:1", server_context=True)
    assert called == []


def test_server_policy_reads_the_allowlist_from_the_environment(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_REGISTRY_ALLOWLIST", " GHCR.io ,registry.example.test:5000,, ")
    policy = RegistryPolicy.for_server()
    assert policy.server and policy.allowlist == frozenset({"ghcr.io", "registry.example.test:5000"})
    assert LOCAL_POLICY.server is False


def test_api_and_mcp_image_scans_run_in_server_context(monkeypatch):
    import asyncio

    from agent_bom.api.scan_discovery_stages import _image_agent
    from agent_bom.mcp_server_scan import run_scan_pipeline

    seen: list[dict[str, Any]] = []

    def fake_scan_image(image_ref, **kwargs):
        seen.append(kwargs)
        return [Package(name="bash", version="5.2", ecosystem="deb")], "registry"

    async def no_vuln_scan(agents, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.image.scan_image", fake_scan_image)
    monkeypatch.setattr("agent_bom.scanners.scan_agents", no_vuln_scan)
    _image_agent(REF, source="image")
    asyncio.run(run_scan_pipeline(safe_path=lambda value: value, image=REF, no_discover=True))

    assert [kwargs.get("server_context") for kwargs in seen] == [True, True]
