"""Cosign image signatures: discovery and keyed verification.

Cosign stores a signature for image digest ``sha256:<hex>`` as the manifest
tagged ``sha256-<hex>.sig``. Each layer is a simple-signing payload whose
``critical.image.docker-manifest-digest`` names the signed digest, with the
base64 signature in the ``dev.cosignproject.cosign/signature`` annotation.

Keyed verification checks the signature over the exact payload bytes with the
operator's public key (ECDSA P-256/P-384/P-521 with SHA-256/SHA-384/SHA-512
by curve, RSA PKCS#1 v1.5 with SHA-256, or Ed25519 — the verifiers cosign
selects for those key types) and
then that the payload names this image's digest. Keyless signatures (a Fulcio
certificate plus a Rekor bundle) are reported as ``present-unverified``:
certificate-chain, identity and transparency-log checks are not implemented.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from agent_bom.image_evidence.model import as_dict
from agent_bom.oci_registry.client import RegistryClient, RegistryError, RegistryLimitError
from agent_bom.oci_registry.media_types import COSIGN_SIMPLESIGNING

SIGNATURE_ANNOTATION = "dev.cosignproject.cosign/signature"
CERTIFICATE_ANNOTATION = "dev.sigstore.cosign/certificate"
BUNDLE_ANNOTATION = "dev.sigstore.cosign/bundle"
_MAX_PAYLOAD_BYTES = 256 * 1024
_MAX_KEY_BYTES = 64 * 1024
MAX_SIGNATURES = 16


class SignatureKeyError(Exception):
    """The operator-supplied public key could not be loaded."""


@dataclass(frozen=True)
class CosignSignature:
    signed_digest: str
    payload: bytes
    signature: bytes
    keyless: bool
    has_bundle: bool


def signature_tag(digest: str) -> str:
    return digest.replace(":", "-", 1) + ".sig"


def load_public_key(path: str) -> Any:
    try:
        data = Path(path).expanduser().read_bytes()
    except OSError as exc:
        raise SignatureKeyError(f"Cosign public key could not be read: {exc.strerror or exc}") from exc
    if len(data) > _MAX_KEY_BYTES:
        raise SignatureKeyError("Cosign public key file is too large")
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise SignatureKeyError("Cosign public key is not a PEM public key") from exc
    if not isinstance(key, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey, ed25519.Ed25519PublicKey)):
        raise SignatureKeyError("Unsupported cosign public key type (expected ECDSA, RSA or Ed25519)")
    return key


def _ecdsa_hash(key: ec.EllipticCurvePublicKey) -> hashes.HashAlgorithm:
    """The digest cosign pairs with an ECDSA key: SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521."""
    if isinstance(key.curve, ec.SECP384R1):
        return hashes.SHA384()
    if isinstance(key.curve, ec.SECP521R1):
        return hashes.SHA512()
    return hashes.SHA256()


def verify_with_key(key: Any, payload: bytes, signature: bytes) -> bool:
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, payload, ec.ECDSA(_ecdsa_hash(key)))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, payload)
        else:
            return False
    except InvalidSignature:
        return False
    return True


def payload_digest(payload: bytes) -> str | None:
    try:
        document = json.loads(payload)
    except ValueError:
        return None
    critical = document.get("critical") if isinstance(document, dict) else None
    image = critical.get("image") if isinstance(critical, dict) else None
    digest = image.get("docker-manifest-digest") if isinstance(image, dict) else None
    return digest if isinstance(digest, str) else None


def fetch_cosign_signatures(client: RegistryClient, digest: str) -> list[CosignSignature]:
    """Signatures stored under the cosign ``.sig`` tag for ``digest`` (empty when there is none)."""
    manifest = client.get_manifest(signature_tag(digest), missing_ok=True)
    if manifest is None:
        return []
    if "layers" not in manifest.document:
        raise RegistryError("Signature manifest has no payload layers")
    found: list[CosignSignature] = []
    seen: set[tuple[str, str]] = set()
    payloads: dict[str, bytes] = {}
    for layer in manifest.document.get("layers") or []:
        if not isinstance(layer, dict) or layer.get("mediaType") != COSIGN_SIMPLESIGNING:
            continue
        annotations = as_dict(layer.get("annotations"))
        digest_key = str(layer.get("digest") or "")
        encoded_signature = str(annotations.get(SIGNATURE_ANNOTATION) or "")
        identity = (digest_key, encoded_signature)
        if identity in seen:
            continue
        if len(seen) >= MAX_SIGNATURES:
            raise RegistryLimitError("Signature count limit reached")
        seen.add(identity)
        try:
            signature = base64.b64decode(encoded_signature, validate=True)
        except (binascii.Error, ValueError):
            raise RegistryError("Signature annotation is not valid base64") from None
        if digest_key not in payloads:
            buffer = io.BytesIO()
            client.fetch_blob(digest_key, buffer, _MAX_PAYLOAD_BYTES)
            payloads[digest_key] = buffer.getvalue()
        payload = payloads[digest_key]
        found.append(
            CosignSignature(
                signed_digest=payload_digest(payload) or "",
                payload=payload,
                signature=signature,
                keyless=bool(annotations.get(CERTIFICATE_ANNOTATION)),
                has_bundle=bool(annotations.get(BUNDLE_ANNOTATION)),
            )
        )
    return found


def signature_verdict(signatures: list[CosignSignature], digests: list[str], key: Any | None) -> dict[str, Any]:
    """Map discovered signatures (and an optional key) to the image's signature status."""
    keyless = any(sig.keyless for sig in signatures)
    if key is not None:
        for sig in signatures:
            if sig.signed_digest in digests and verify_with_key(key, sig.payload, sig.signature):
                return {
                    "status": "verified",
                    "method": "cosign-key",
                    "signed_digest": sig.signed_digest,
                    "detail": "Cosign signature verified with the provided public key.",
                }
        return {
            "status": "invalid",
            "method": "cosign-key",
            "signature_count": len(signatures),
            "detail": "A cosign signature is present but none verified with the provided public key for this image digest.",
        }
    if keyless:
        detail = (
            "Keyless (Fulcio certificate) cosign signature present; "
            "certificate identity and transparency-log verification are not performed."
        )
    else:
        detail = "Cosign signature present; pass a public key (--image-cosign-key) to verify it."
    return {
        "status": "present-unverified",
        "method": "keyless" if keyless else "cosign",
        "signature_count": len(signatures),
        "detail": detail,
    }
