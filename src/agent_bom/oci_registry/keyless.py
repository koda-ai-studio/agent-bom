"""Offline verification of Sigstore image-signature bundles under operator policy."""

from __future__ import annotations

import io
import json
from typing import Any

from agent_bom.core.image_ref import is_image_digest
from agent_bom.image_evidence.model import ImageEvidence, as_dict
from agent_bom.oci_registry.client import RegistryClient, RegistryError, RegistryLimitError
from agent_bom.oci_registry.media_types import SIGSTORE_BUNDLE_PREFIX

MAX_BUNDLE_BYTES = 1024 * 1024
MAX_BUNDLES = 16
_SIGN_PREDICATE = "https://sigstore.dev/cosign/sign/v1"


def signed_image_digest(content_type: str, payload: bytes, candidates: list[str]) -> str | None:
    """Require an image-signature statement; provenance alone is not image approval."""
    if content_type != "application/vnd.in-toto+json":
        return None
    document = json.loads(payload)
    if not isinstance(document, dict) or document.get("_type") != "https://in-toto.io/Statement/v1":
        return None
    if document.get("predicateType") != _SIGN_PREDICATE:
        return None
    subjects = document.get("subject")
    if not isinstance(subjects, list):
        return None
    for subject in subjects:
        digests = as_dict(as_dict(subject).get("digest"))
        for candidate in candidates:
            if is_image_digest(candidate):
                algorithm, value = candidate.split(":", 1)
                if digests.get(algorithm) == value:
                    return candidate
    return None


def verify_bundle(raw: bytes, digests: list[str], identity: str, issuer: str) -> dict[str, Any]:
    """Verify certificate, signer, log proof, timestamp and DSSE subject offline."""
    try:
        from sigstore import errors, models, verify
        from sigstore.verify import policy
    except ImportError:
        return {"status": "unknown", "detail": "Keyless verification requires agent-bom[sigstore]."}
    if len(raw) > MAX_BUNDLE_BYTES:
        return {"status": "unknown", "detail": "Sigstore bundle exceeds the verification size limit."}
    try:
        verifier = verify.Verifier.production(offline=True)
    except Exception:
        return {"status": "unknown", "detail": "Offline Sigstore trust material is unavailable or invalid."}
    try:
        bundle = models.Bundle.from_json(raw)
        content_type, payload = verifier.verify_dsse(bundle, policy.Identity(identity=identity, issuer=issuer))
        digest = signed_image_digest(content_type, payload, digests)
    except (errors.Error, ValueError, TypeError):
        return {"status": "invalid", "method": "sigstore-keyless", "detail": "Sigstore image signature failed verification."}
    except Exception:
        # A local trust-store/runtime failure is not proof that the image is unsigned.
        return {"status": "unknown", "method": "sigstore-keyless", "detail": "Sigstore verification could not complete."}
    if digest is None:
        return {"status": "invalid", "method": "sigstore-keyless", "detail": "Verified bundle is not an image signature for this digest."}
    return {
        "status": "verified",
        "method": "sigstore-keyless",
        "signed_digest": digest,
        "signer_identity": identity,
        "signer_issuer": issuer,
        "trust_source": "sigstore-offline-cache-or-bundled-root",
        "detail": "Image signature, signer identity, issuer and transparency evidence verified using offline trust material.",
    }


def keyless_signature_status(client: RegistryClient, evidence: ImageEvidence, digests: list[str]) -> dict[str, Any] | None:
    """Read digest-verified bundles within the caller's shared evidence budget."""
    identity, issuer = evidence.signer_identity, evidence.signer_issuer
    if not identity and not issuer:
        return None
    if not identity or not issuer or len(identity) > 2048 or len(issuer) > 2048 or evidence.cosign_key_path:
        return {"status": "unknown", "detail": "Configure both an exact signer identity and issuer, or a public key, not both modes."}
    entries = [r for r in evidence.referrers if r["artifact_type"].startswith(SIGSTORE_BUNDLE_PREFIX)]
    if not entries:
        return None
    seen: set[str] = set()
    result: dict[str, Any] = {"status": "invalid", "detail": "No supported Sigstore image-signature bundle verified."}
    for entry in entries:
        manifest = client.get_manifest(entry["digest"])
        if manifest is None or as_dict(manifest.document.get("subject")).get("digest") not in digests:
            raise RegistryError("Sigstore artifact manifest does not bind the requested image")
        for layer in manifest.document.get("layers") or []:
            if not str(layer.get("mediaType", "")).startswith(SIGSTORE_BUNDLE_PREFIX) or layer["digest"] in seen:
                continue
            if len(seen) >= MAX_BUNDLES:
                raise RegistryLimitError("Sigstore bundle count limit reached")
            seen.add(layer["digest"])
            buffer = io.BytesIO()
            client.fetch_blob(layer["digest"], buffer, MAX_BUNDLE_BYTES)
            verdict = verify_bundle(buffer.getvalue(), digests, identity, issuer)
            if verdict["status"] == "verified":
                return verdict
            if verdict["status"] == "unknown" or result["status"] != "unknown":
                result = verdict
    return result
