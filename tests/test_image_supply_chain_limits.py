"""Hostile signature and attestation lists must not multiply registry requests without a bound."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from agent_bom.image_evidence.model import ImageEvidence
from agent_bom.oci_registry import client as client_module
from agent_bom.oci_registry.client import RegistryClient, RegistryError, sha256_digest
from agent_bom.oci_registry.media_types import COSIGN_SIMPLESIGNING, DOCKER_REFERENCE_DIGEST
from agent_bom.oci_registry.reference import parse_reference
from agent_bom.oci_registry.signatures import SIGNATURE_ANNOTATION, fetch_cosign_signatures
from agent_bom.oci_registry.supply_chain import discover_supply_chain
from agent_bom.scanners.state import consume_coverage_warnings

SUBJECT = "sha256:" + "a" * 64


def _client(handler):
    return RegistryClient(parse_reference("registry.example.test/team/app:1"), transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("duplicate", [False, True])
def test_signature_downloads_are_capped_and_deduplicated(duplicate):
    payloads = {}
    layers = []
    for i in range(100):
        raw = json.dumps({"critical": {"image": {"docker-manifest-digest": SUBJECT}}, "index": 0 if duplicate else i}).encode()
        digest = sha256_digest(raw)
        payloads[digest] = raw
        layers.append({"mediaType": COSIGN_SIMPLESIGNING, "digest": digest, "annotations": {SIGNATURE_ANNOTATION: "AA=="}})
    fetched = []

    def handler(request):
        if "/manifests/" in request.url.path:
            return httpx.Response(200, json={"layers": layers})
        digest = request.url.path.rsplit("/", 1)[1]
        fetched.append(digest)
        return httpx.Response(200, content=payloads[digest])

    with _client(handler) as client:
        if duplicate:
            found = fetch_cosign_signatures(client, SUBJECT)
            assert len(found) == 1
            assert len(fetched) == 1
        else:
            with pytest.raises(RegistryError, match="limit"):
                fetch_cosign_signatures(client, SUBJECT)
            assert len(fetched) <= 16


def test_buildkit_fanout_is_bounded_and_records_incomplete_coverage():
    manifests = {}
    descriptors = []
    for i in range(100):
        raw = json.dumps({"layers": [{"digest": f"sha256:{i:064x}", "mediaType": "application/vnd.in-toto+json"}]}).encode()
        digest = sha256_digest(raw)
        manifests[digest] = raw
        descriptors.append(
            {
                "digest": digest,
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {DOCKER_REFERENCE_DIGEST: SUBJECT, "vnd.docker.reference.type": "attestation-manifest"},
            }
        )
    fetched = []

    def handler(request):
        digest = request.url.path.rsplit("/", 1)[1]
        if digest in manifests:
            fetched.append(digest)
            return httpx.Response(200, content=manifests[digest])
        return httpx.Response(404)

    evidence = ImageEvidence("registry.example.test/team/app:1", digest=SUBJECT)
    with _client(handler) as client:
        discover_supply_chain(client, evidence, {"manifests": descriptors})
    assert len(fetched) <= 50
    assert evidence.signature["status"] == "unknown"
    assert any(w["reason"] == "image_supply_chain_incomplete" for w in consume_coverage_warnings())


def test_budget_bounds_total_bytes_and_requests_and_closes_responses():
    responses = []

    def handler(request):
        response = httpx.Response(200, content=b'{"layers": []}')
        responses.append(response)
        return response

    with _client(handler) as client:
        with client.bounded_evidence(max_bytes=20):
            client.get_manifest("1")
            with pytest.raises(RegistryError, match="aggregate byte limit"):
                client.get_manifest("2")
        assert all(response.is_closed for response in responses)
        before = len(responses)
        with client.bounded_evidence(max_requests=1):
            client.get_manifest("3")
            with pytest.raises(RegistryError, match="request limit"):
                client.get_manifest("4")
        assert len(responses) == before + 1
        assert client._evidence_budget is None


def test_budget_deadline_caps_network_timeout_and_stops_later_requests(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(client_module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    calls = []

    def handler(request):
        calls.append(request)
        assert all(value <= 2.0 for value in request.extensions["timeout"].values())
        return httpx.Response(200, json={"layers": []})

    with _client(handler) as client, client.bounded_evidence(seconds=2):
        client.get_manifest("1")
        now[0] = 103.0
        with pytest.raises(RegistryError, match="time limit"):
            client.get_manifest("2")
    assert len(calls) == 1


def test_unreadable_signature_blob_is_unknown_with_coverage_gap():
    def handler(request):
        if request.url.path.endswith(".sig"):
            return httpx.Response(
                200,
                json={"layers": [{"mediaType": COSIGN_SIMPLESIGNING, "digest": SUBJECT, "annotations": {SIGNATURE_ANNOTATION: "AA=="}}]},
            )
        return httpx.Response(404)

    evidence = ImageEvidence("registry.example.test/team/app:1", digest=SUBJECT)
    with _client(handler) as client:
        discover_supply_chain(client, evidence, None)
    assert evidence.signature["status"] == "unknown"
    assert any(w["reason"] == "image_supply_chain_incomplete" for w in consume_coverage_warnings())


def test_sha512_identity_drives_signatures_referrers_and_descriptor_annotations():
    import hashlib

    from agent_bom.oci_registry.manifests import index_annotations

    raw = b'{"schemaVersion":2,"layers":[]}'
    digest = "sha512:" + hashlib.sha512(raw).hexdigest()
    paths = []

    def handler(request):
        paths.append(request.url.path)
        if request.url.path.endswith("/manifests/1"):
            return httpx.Response(200, content=raw, headers={"Docker-Content-Digest": digest})
        return httpx.Response(404)

    with _client(handler) as client:
        manifest = client.get_manifest("1")
        evidence = ImageEvidence("registry.example.test/team/app:1", digest=manifest.digest)
        index = {"manifests": [{"digest": digest, "annotations": {"fixture.platform": "selected"}}]}
        discover_supply_chain(client, evidence, index)
    assert evidence.digest == digest
    assert any(path.endswith("/referrers/" + digest) for path in paths)
    assert any(path.endswith("/manifests/" + digest.replace(":", "-", 1) + ".sig") for path in paths)
    assert index_annotations(index, evidence.digest) == {"fixture.platform": "selected"}
    assert evidence.signature["status"] == "unsigned"
