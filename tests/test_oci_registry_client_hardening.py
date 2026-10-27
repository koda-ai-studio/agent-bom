"""Registry client limits: bounded reads, no credential replay to redirect hosts, every digest algorithm verified."""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from agent_bom.oci_registry import client as registry_client
from agent_bom.oci_registry.auth import RegistryCredential
from agent_bom.oci_registry.client import RegistryClient, RegistryError
from agent_bom.oci_registry.reference import parse_reference

_REF = parse_reference("registry.example.test/team/app:1")
_MANIFEST = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": []}).encode()


def _client(handler, **kwargs) -> RegistryClient:
    return RegistryClient(_REF, transport=httpx.MockTransport(handler), **kwargs)


class _Chunks:
    def __init__(self, chunk: bytes, count: int) -> None:
        self.chunk, self.count, self.served = chunk, count, 0

    def __iter__(self):
        for _ in range(self.count):
            self.served += 1
            yield self.chunk


@pytest.mark.parametrize("path", ["manifests/1", "referrers/sha256:" + "a" * 64])
def test_oversized_manifest_and_referrers_bodies_stop_at_the_cap(monkeypatch, path):
    monkeypatch.setattr(registry_client, "MAX_MANIFEST_BYTES", 64 * 1024)
    body = _Chunks(b"x" * 16 * 1024, 10_000)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"Content-Type": "application/vnd.oci.image.index.v1+json"})

    client = _client(handler)
    with pytest.raises(RegistryError, match="size limit"):
        client.get_manifest("1") if path.startswith("manifests") else client.referrers("sha256:" + "a" * 64)
    assert body.served <= 6, f"read {body.served} chunks past a 64 KiB cap"


def test_401_from_a_redirect_host_never_receives_the_registry_credentials():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "registry.example.test":
            return httpx.Response(307, headers={"Location": "https://cdn.example.test/blob"})
        if request.url.host == "cdn.example.test":
            return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="https://collector.example.test/token",service="x"'})
        return httpx.Response(200, json={"token": "stolen"})

    secret = "registry-" + "pass"
    client = _client(handler, credential_resolver=lambda: RegistryCredential(source="explicit", username="u", password=secret))
    with pytest.raises(RegistryError):
        client.get_manifest("1")

    assert not [r for r in seen if r.url.host == "collector.example.test"]
    assert all("authorization" not in r.headers for r in seen)


def _serving(raw: bytes, header_digest: str | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"Content-Type": "application/vnd.oci.image.manifest.v1+json"}
        if header_digest:
            headers["Docker-Content-Digest"] = header_digest
        return httpx.Response(200, content=raw, headers=headers)

    return handler


def test_sha512_manifest_digests_are_verified():
    good = "sha512:" + hashlib.sha512(_MANIFEST).hexdigest()
    assert _client(_serving(_MANIFEST)).get_manifest(good) is not None
    assert _client(_serving(_MANIFEST, good)).get_manifest("1") is not None

    wrong = "sha512:" + hashlib.sha512(b"other").hexdigest()
    with pytest.raises(RegistryError, match="does not match"):
        _client(_serving(_MANIFEST)).get_manifest(wrong)
    with pytest.raises(RegistryError, match="does not match"):
        _client(_serving(_MANIFEST, wrong)).get_manifest("1")


def test_unknown_digest_algorithms_are_rejected():
    with pytest.raises(RegistryError, match="Unsupported digest algorithm"):
        _client(_serving(_MANIFEST, "md5:" + hashlib.md5(_MANIFEST).hexdigest())).get_manifest("1")  # noqa: S324
