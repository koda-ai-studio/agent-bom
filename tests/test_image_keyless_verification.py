"""Real public Sigstore image bundle, verified offline with exact signer policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.image_evidence import collect_image_evidence
from agent_bom.image_evidence.surfaces import signature_policy_violation
from agent_bom.oci_registry.client import RegistryClient
from agent_bom.oci_registry.reference import parse_reference
from agent_bom.oci_registry.supply_chain import discover_supply_chain
from tests._oci_image_builder import OCI_MANIFEST
from tests._oci_registry_fake import REGISTRY, FakeRegistry

pytest.importorskip("sigstore")

DIGEST = "sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d"
IDENTITY = "keyless@projectsigstore.iam.gserviceaccount.com"
ISSUER = "https://accounts.google.com"
BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
REF = f"{REGISTRY}/team/app@{DIGEST}"
FIXTURE = Path(__file__).parent / "fixtures" / "sigstore" / "cosign-v3.1.4.bundle.json"


def _discover(monkeypatch, *, identity=IDENTITY, issuer=ISSUER, digest=DIGEST, bundle=None):
    for name, value in (("AGENT_BOM_IMAGE_SIGNER_IDENTITY", identity), ("AGENT_BOM_IMAGE_SIGNER_ISSUER", issuer)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    monkeypatch.delenv("AGENT_BOM_IMAGE_COSIGN_KEY", raising=False)
    registry = FakeRegistry()
    raw = FIXTURE.read_bytes() if bundle is None else json.dumps(bundle).encode()
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": BUNDLE_TYPE,
        "subject": {"mediaType": OCI_MANIFEST, "digest": digest, "size": 1},
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": registry.add_blob(b"{}"), "size": 2},
        "layers": [{"mediaType": BUNDLE_TYPE, "digest": registry.add_blob(raw), "size": len(raw)}],
    }
    manifest_raw = json.dumps(manifest).encode()
    manifest_digest = registry.add_manifest("team/app", manifest_raw, OCI_MANIFEST)
    registry.referrers[("team/app", digest)] = [
        {
            "mediaType": OCI_MANIFEST,
            "artifactType": BUNDLE_TYPE,
            "digest": manifest_digest,
            "size": len(manifest_raw),
        }
    ]
    with collect_image_evidence(REF) as evidence, RegistryClient(parse_reference(REF), transport=registry.transport()) as client:
        evidence.digest = digest
        discover_supply_chain(client, evidence, None)
    return evidence


def test_real_keyless_image_signature_verifies_without_network(monkeypatch):
    import socket

    def no_network(*args, **kwargs):
        raise AssertionError("Keyless verification must use bundled/cached trust material offline")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    evidence = _discover(monkeypatch)
    assert evidence.signature["status"] == "verified"
    assert evidence.signature["method"] == "sigstore-keyless"
    assert evidence.signature["signed_digest"] == DIGEST
    assert signature_policy_violation(evidence, True) is None


@pytest.mark.parametrize("change", ["identity", "issuer", "digest", "signature", "proof"])
def test_keyless_verification_rejects_wrong_binding_or_tampered_evidence(monkeypatch, change):
    kwargs = {}
    if change == "identity":
        kwargs["identity"] = "wrong@example.invalid"
    elif change == "issuer":
        kwargs["issuer"] = "https://issuer.example.invalid"
    elif change == "digest":
        kwargs["digest"] = "sha256:" + "a" * 64
    else:
        bundle = json.loads(FIXTURE.read_bytes())
        if change == "signature":
            bundle["dsseEnvelope"]["signatures"][0]["sig"] = "AAAA"
        else:
            bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"] = "AAAA"
        kwargs["bundle"] = bundle
    evidence = _discover(monkeypatch, **kwargs)
    assert evidence.signature["status"] == "invalid"
    assert signature_policy_violation(evidence, True) is not None


def test_keyless_bundle_presence_is_not_verification_without_policy(monkeypatch):
    evidence = _discover(monkeypatch, identity=None, issuer=None)
    assert evidence.signature["status"] == "present-unverified"
    assert signature_policy_violation(evidence, True) is not None


def test_partial_signer_policy_fails_closed(monkeypatch):
    evidence = _discover(monkeypatch, issuer=None)
    assert evidence.signature["status"] == "unknown"
    assert signature_policy_violation(evidence, True) is not None


def test_provenance_subject_is_not_an_image_signature():
    from agent_bom.oci_registry.keyless import signed_image_digest

    payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"digest": {"sha256": DIGEST.split(":")[1]}}],
    }
    assert signed_image_digest("application/vnd.in-toto+json", json.dumps(payload).encode(), [DIGEST]) is None
    payload["predicateType"] = "https://sigstore.dev/cosign/sign/v1"
    assert signed_image_digest("application/vnd.in-toto+json", json.dumps(payload).encode(), [DIGEST]) == DIGEST
    assert signed_image_digest("text/plain", json.dumps(payload).encode(), [DIGEST]) is None


def test_missing_optional_library_is_unknown(monkeypatch):
    import builtins

    from agent_bom.oci_registry.keyless import verify_bundle

    original = builtins.__import__

    def without_sigstore(name, *args, **kwargs):
        if name.startswith("sigstore"):
            raise ImportError("optional library is absent")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_sigstore)
    result = verify_bundle(FIXTURE.read_bytes(), [DIGEST], IDENTITY, ISSUER)
    assert result["status"] == "unknown"


def test_policy_is_preserved_on_image_strategy_restart(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_IMAGE_SIGNER_IDENTITY", IDENTITY)
    monkeypatch.setenv("AGENT_BOM_IMAGE_SIGNER_ISSUER", ISSUER)
    with collect_image_evidence(REF) as evidence:
        evidence.signature = {"status": "invalid"}
        evidence.restart()
        assert (evidence.signer_identity, evidence.signer_issuer) == (IDENTITY, ISSUER)
        assert evidence.signature["status"] == "unknown"
