"""Image references resolve to the registry API host, repository and tag/digest the distribution API needs."""

from __future__ import annotations

import pytest

from agent_bom.oci_registry.reference import ImageReference, ReferenceError, parse_reference

_DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize(
    ("raw", "registry", "repository", "tag", "digest"),
    [
        ("nginx", "registry-1.docker.io", "library/nginx", "latest", None),
        ("nginx:1.27", "registry-1.docker.io", "library/nginx", "1.27", None),
        ("docker.io/library/nginx:1.27", "registry-1.docker.io", "library/nginx", "1.27", None),
        ("index.docker.io/bitnami/redis", "registry-1.docker.io", "bitnami/redis", "latest", None),
        ("bitnami/redis:7", "registry-1.docker.io", "bitnami/redis", "7", None),
        ("ghcr.io/org/app:v1.0.0", "ghcr.io", "org/app", "v1.0.0", None),
        ("localhost:5000/team/app:dev", "localhost:5000", "team/app", "dev", None),
        (f"ghcr.io/org/app@{_DIGEST}", "ghcr.io", "org/app", None, _DIGEST),
        (f"ghcr.io/org/app:v1@{_DIGEST}", "ghcr.io", "org/app", "v1", _DIGEST),
        ("registry.example.test/a/b/c:1", "registry.example.test", "a/b/c", "1", None),
    ],
)
def test_parse_reference_normalizes_docker_hub_and_custom_registries(raw, registry, repository, tag, digest):
    ref = parse_reference(raw)
    assert (ref.registry, ref.repository, ref.tag, ref.digest) == (registry, repository, tag, digest)
    assert ref.manifest_ref == (digest or tag)


def test_docker_hub_credential_keys_include_legacy_index_url():
    assert "https://index.docker.io/v1/" in parse_reference("nginx").credential_keys()
    assert parse_reference("ghcr.io/org/app").credential_keys()[0] == "ghcr.io"


@pytest.mark.parametrize(
    "raw",
    ["", "-rm", "UPPER/case", "ghcr.io/org/app@sha256:short", "ghcr.io/org/app:bad tag", "a" * 300, "ghcr.io//app"],
)
def test_parse_reference_rejects_malformed_references(raw):
    with pytest.raises(ReferenceError):
        parse_reference(raw)


def test_only_loopback_registries_may_use_plain_http():
    assert parse_reference("localhost:5000/app").allows_plain_http
    assert parse_reference("127.0.0.1:5000/app").allows_plain_http
    assert not parse_reference("ghcr.io/org/app").allows_plain_http
    assert isinstance(parse_reference("nginx"), ImageReference)
