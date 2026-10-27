"""Every image-reference parser splits a reference the same way as ``core.image_ref``."""

from __future__ import annotations

import pytest

from agent_bom.cloud.container_sbom import _parse_image_ref
from agent_bom.cloud.normalization import parse_container_image_package
from agent_bom.core.image_ref import digest_in_ref, image_repository, parse_image_ref
from agent_bom.models import MCPServer
from agent_bom.parsers import _split_container_image_ref, detect_docker_image_package

_D = "sha256:" + "ab" * 32

# reference -> (name, registry, path, tag, digest)
CASES = {
    "ubuntu": ("ubuntu", "docker.io", "library/ubuntu", "", ""),
    "ubuntu:22.04": ("ubuntu", "docker.io", "library/ubuntu", "22.04", ""),
    "pytorch/pytorch:2.1.0": ("pytorch/pytorch", "docker.io", "pytorch/pytorch", "2.1.0", ""),
    "docker.io/nginx:1.25": ("docker.io/nginx", "docker.io", "library/nginx", "1.25", ""),
    "localhost/img": ("localhost/img", "localhost", "img", "", ""),
    "host:5000/img:tag": ("host:5000/img", "host:5000", "img", "tag", ""),
    "localhost:5000/team/img": ("localhost:5000/team/img", "localhost:5000", "team/img", "", ""),
    "nvcr.io/nvidia/cuda:12.3": ("nvcr.io/nvidia/cuda", "nvcr.io", "nvidia/cuda", "12.3", ""),
    "ghcr.io/org/team/sub/app:v1": ("ghcr.io/org/team/sub/app", "ghcr.io", "org/team/sub/app", "v1", ""),
    f"ghcr.io/org/app@{_D}": ("ghcr.io/org/app", "ghcr.io", "org/app", "", _D),
    f"ghcr.io/org/app:1.2@{_D}": ("ghcr.io/org/app", "ghcr.io", "org/app", "1.2", _D),
    f"host:5000/img:tag@{_D}": ("host:5000/img", "host:5000", "img", "tag", _D),
    f"alpine@{_D}": ("alpine", "docker.io", "library/alpine", "", _D),
    "Registry.Example/Org/App:V1": ("Registry.Example/Org/App", "Registry.Example", "Org/App", "V1", ""),
    "  busybox:1.36  ": ("busybox", "docker.io", "library/busybox", "1.36", ""),
}


@pytest.mark.parametrize("ref", list(CASES))
def test_core_parser_splits_every_part(ref: str) -> None:
    name, registry, path, tag, digest = CASES[ref]
    parsed = parse_image_ref(ref)
    assert (parsed.name, parsed.registry, parsed.path, parsed.tag, parsed.digest) == (name, registry, path, tag, digest)
    assert image_repository(ref) == name
    assert digest_in_ref(ref) == digest
    assert parsed.version == (digest or tag or "latest")


@pytest.mark.parametrize("ref", list(CASES))
def test_package_parsers_agree_with_core(ref: str) -> None:
    name, _registry, _path, tag, digest = CASES[ref]
    version = digest or tag or "latest"
    assert parse_container_image_package(ref) == (name, version)
    assert _split_container_image_ref(ref) == (name, version)


@pytest.mark.parametrize("ref", list(CASES))
def test_container_sbom_parser_agrees_with_core(ref: str) -> None:
    _name, registry, path, tag, digest = CASES[ref]
    org, _, repo = path.partition("/") if "/" in path else ("library", "", path)
    assert _parse_image_ref(ref) == (registry, org, repo, digest or tag or "latest")


def test_tag_and_digest_never_leak_into_the_repository() -> None:
    ref = f"ghcr.io/org/app:1.2@{_D}"
    registry, org, repo, reference = _parse_image_ref(ref)
    assert (registry, org, repo, reference) == ("ghcr.io", "org", "app", _D)
    [package] = detect_docker_image_package(MCPServer(name="app", command="docker", args=["run", "--rm", ref]))
    assert (package.name, package.version) == ("ghcr.io/org/app", _D)
    assert package.purl == f"pkg:docker/ghcr.io/org/app@{_D.replace(':', '%3A')}"


@pytest.mark.parametrize("ref", ["", "   ", ":tag", f"@{_D}"])
def test_empty_or_nameless_references_are_rejected(ref: str) -> None:
    assert parse_container_image_package(ref) is None
    assert parse_image_ref(ref).name == ""


@pytest.mark.parametrize("ref", [r for r in CASES if r == r.lower()])
def test_strict_registry_parser_agrees_with_core(ref: str) -> None:
    from agent_bom.oci_registry.reference import parse_reference

    parsed, strict = parse_image_ref(ref), parse_reference(ref)
    assert (strict.repository, strict.digest or "", strict.manifest_ref) == (parsed.path, parsed.digest, parsed.version)


def test_strict_registry_parser_rejects_uppercase_repository() -> None:
    from agent_bom.oci_registry.reference import ReferenceError, parse_reference

    with pytest.raises(ReferenceError):
        parse_reference("Registry.Example/Org/App:V1")


@pytest.mark.parametrize("ref", [f"ghcr.io/modelcontextprotocol/server:1.2@{_D}", "mcp/fetch:0.6", "mcp/fetch"])
def test_compose_discovery_names_the_image_like_core(ref: str, tmp_path) -> None:
    from agent_bom.discovery import discover_compose_mcp_servers

    (tmp_path / "docker-compose.yml").write_text(f"services:\n  svc:\n    image: {ref}\n")
    agent = discover_compose_mcp_servers(str(tmp_path))
    assert agent is not None
    [package] = agent.mcp_servers[0].packages
    parsed = parse_image_ref(ref)
    assert (package.name, package.version) == (parsed.name, parsed.version)


@pytest.mark.parametrize(
    ("ref", "floating"),
    [("ubuntu", True), ("ubuntu:latest", True), ("host:5000/img", True), ("ubuntu:22.04", False), (f"ubuntu:latest@{_D}", False)],
)
def test_floating_image_classifier_uses_core_split(ref: str, floating: bool) -> None:
    from agent_bom.floating_refs import classify_image_reference

    assert (classify_image_reference(ref) is not None) is floating


@pytest.mark.parametrize("digest", ["sha256:" + "a" * 64, "sha512:" + "b" * 128])
def test_supported_digest_identity_and_kubernetes_status_agree(digest):
    from agent_bom.core.image_ref import image_key
    from agent_bom.kubernetes.inventory import image_digest_from_status

    assert image_key("registry.example/app:tag", digest) == f"registry.example/app@{digest}"
    assert image_digest_from_status(f"docker-pullable://registry.example/app@{digest}") == digest


@pytest.mark.parametrize("digest", ["sha512:short", "sha256:short", "sha512:" + "z" * 128, "md5:" + "a" * 32])
def test_malformed_digest_is_not_promoted_to_verified_identity(digest):
    from agent_bom.core.image_ref import image_key
    from agent_bom.kubernetes.inventory import image_digest_from_status

    assert image_key("registry.example/app:tag", digest) == "registry.example/app:tag"
    assert image_digest_from_status(f"docker-pullable://registry.example/app@{digest}") == ""
