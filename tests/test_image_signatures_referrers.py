"""Cosign signatures are verified with a provided key, keyless ones are reported honestly, referrers are listed."""

from __future__ import annotations

import base64
import json
import shutil

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from agent_bom.image import scan_image
from agent_bom.image_evidence import collect_image_evidence
from agent_bom.oci_registry import client as registry_client
from tests._oci_image_builder import OCI_INDEX, OCI_MANIFEST, build_image, build_index, digest_of, dpkg_status
from tests._oci_registry_fake import REGISTRY, FakeRegistry

REF = f"{REGISTRY}/team/app:1.0"
SIMPLESIGNING = "application/vnd.dev.cosign.simplesigning.v1+json"


@pytest.fixture
def registry(monkeypatch):
    fake = FakeRegistry()
    monkeypatch.setattr(registry_client, "_default_transport", fake.transport)
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    image = build_image([{"var/lib/dpkg/status": dpkg_status(("bash", "5.2"))}])
    fake.push_image("team/app", image, "1.0")
    fake.image = image  # type: ignore[attr-defined]
    return fake


def _write_key(tmp_path, private_key) -> str:
    pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    path = tmp_path / "cosign.pub"
    path.write_bytes(pem)
    return str(path)


def _payload(digest: str) -> bytes:
    body = {
        "critical": {
            "identity": {"docker-reference": f"{REGISTRY}/team/app"},
            "image": {"docker-manifest-digest": digest},
            "type": "cosign container image signature",
        },
        "optional": None,
    }
    return json.dumps(body).encode()


def _push_signature(registry: FakeRegistry, digest: str, payload: bytes, signature: bytes, *, certificate: bool = False) -> None:
    payload_digest = registry.add_blob(payload)
    annotations = {"dev.cosignproject.cosign/signature": base64.b64encode(signature).decode()}
    if certificate:
        annotations["dev.sigstore.cosign/certificate"] = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    config = registry.add_blob(b"{}")
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": 2},
        "layers": [{"mediaType": SIMPLESIGNING, "digest": payload_digest, "size": len(payload), "annotations": annotations}],
    }
    registry.add_manifest("team/app", json.dumps(manifest).encode(), OCI_MANIFEST, digest.replace(":", "-") + ".sig")


def _scan(key_path: str | None = None):
    with collect_image_evidence(REF, cosign_key_path=key_path) as evidence:
        scan_image(REF)
    return evidence


def test_unsigned_image_is_reported_unsigned(registry):
    assert _scan().signature["status"] == "unsigned"


@pytest.mark.parametrize("algorithm", ["ecdsa", "ed25519"])
def test_keyed_signature_verifies_with_the_matching_public_key(registry, tmp_path, algorithm):
    digest = registry.image.manifest_digest
    payload = _payload(digest)
    if algorithm == "ecdsa":
        private = ec.generate_private_key(ec.SECP256R1())
        signature = private.sign(payload, ec.ECDSA(hashes.SHA256()))
    else:
        private = ed25519.Ed25519PrivateKey.generate()
        signature = private.sign(payload)
    _push_signature(registry, digest, payload, signature)

    evidence = _scan(_write_key(tmp_path, private))

    assert evidence.signature["status"] == "verified"
    assert evidence.signature["signed_digest"] == digest


@pytest.mark.parametrize(
    "curve,hash_algorithm",
    [(ec.SECP256R1(), hashes.SHA256()), (ec.SECP384R1(), hashes.SHA384()), (ec.SECP521R1(), hashes.SHA512())],
    ids=["p256-sha256", "p384-sha384", "p521-sha512"],
)
def test_ecdsa_verification_selects_the_hash_cosign_uses_for_the_curve(registry, tmp_path, curve, hash_algorithm):
    """cosign signs P-256/P-384/P-521 keys with SHA-256/SHA-384/SHA-512 respectively."""
    digest = registry.image.manifest_digest
    payload = _payload(digest)
    private = ec.generate_private_key(curve)
    _push_signature(registry, digest, payload, private.sign(payload, ec.ECDSA(hash_algorithm)))

    evidence = _scan(_write_key(tmp_path, private))

    assert evidence.signature["status"] == "verified"
    assert evidence.signature["signed_digest"] == digest


def test_p384_signature_made_with_the_wrong_hash_is_invalid(registry, tmp_path):
    digest = registry.image.manifest_digest
    payload = _payload(digest)
    private = ec.generate_private_key(ec.SECP384R1())
    _push_signature(registry, digest, payload, private.sign(payload, ec.ECDSA(hashes.SHA256())))

    assert _scan(_write_key(tmp_path, private)).signature["status"] == "invalid"


def test_wrong_key_or_wrong_digest_is_invalid_not_verified(registry, tmp_path):
    digest = registry.image.manifest_digest
    signer = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    payload = _payload(digest)
    _push_signature(registry, digest, payload, signer.sign(payload, ec.ECDSA(hashes.SHA256())))

    assert _scan(_write_key(tmp_path, other)).signature["status"] == "invalid"

    swapped = _payload("sha256:" + "f" * 64)
    _push_signature(registry, digest, swapped, signer.sign(swapped, ec.ECDSA(hashes.SHA256())))
    assert _scan(_write_key(tmp_path, signer)).signature["status"] == "invalid"


def test_signature_without_key_is_present_unverified_and_keyless_is_not_claimed_verified(registry):
    digest = registry.image.manifest_digest
    _push_signature(registry, digest, _payload(digest), b"\x30\x00", certificate=True)

    signature = _scan().signature

    assert signature["status"] == "present-unverified"
    assert signature["method"] == "keyless"
    assert "not performed" in signature["detail"]


def test_unreadable_key_leaves_status_unknown(registry, tmp_path):
    (tmp_path / "bad.pub").write_text("not a key")
    assert _scan(str(tmp_path / "bad.pub")).signature["status"] == "unknown"


def test_referrers_api_lists_sbom_and_sigstore_bundle(registry):
    digest = registry.image.manifest_digest
    registry.referrers[("team/app", digest)] = [
        {"mediaType": OCI_MANIFEST, "digest": "sha256:" + "1" * 64, "size": 1, "artifactType": "application/spdx+json"},
        {
            "mediaType": OCI_MANIFEST,
            "digest": "sha256:" + "2" * 64,
            "size": 1,
            "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        },
    ]

    evidence = _scan()

    kinds = sorted((r["kind"], r["source"]) for r in evidence.referrers)
    assert kinds == [("sbom", "referrers-api"), ("signature", "referrers-api")]
    assert evidence.signature["status"] == "present-unverified"
    assert evidence.signature["method"] == "sigstore-bundle"


def test_referrers_tag_schema_fallback_and_buildkit_attestations(registry):
    registry.referrers_api = False
    image = registry.image
    tag_index = {
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [
            {"mediaType": OCI_MANIFEST, "digest": "sha256:" + "3" * 64, "size": 1, "artifactType": "application/vnd.cyclonedx+json"}
        ],
    }
    registry.add_manifest("team/app", json.dumps(tag_index).encode(), OCI_INDEX, image.manifest_digest.replace(":", "-"))
    raw, index_digest = build_index({"linux/amd64": image}, attestation_for="linux/amd64")
    attestation = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": registry.add_blob(b"{}"), "size": 2},
        "layers": [
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": "sha256:" + "4" * 64,
                "size": 1,
                "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"},
            }
        ],
    }
    attestation_raw = json.dumps(attestation).encode()
    index = json.loads(raw)
    index["manifests"][-1]["digest"] = digest_of(attestation_raw)
    registry.add_manifest("team/app", attestation_raw, OCI_MANIFEST)
    registry.add_manifest("team/app", json.dumps(index).encode(), OCI_INDEX, "1.0")
    assert index_digest

    evidence = _scan()

    found = sorted((r["kind"], r["source"]) for r in evidence.referrers)
    assert ("sbom", "referrers-tag-schema") in found
    assert ("provenance", "buildkit-attestation-manifest") in found
    assert evidence.signature["status"] == "unsigned"
