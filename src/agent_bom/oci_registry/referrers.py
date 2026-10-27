"""Discover artifacts attached to an image digest: SBOMs, provenance, attestations, signatures.

Sources, in order: the OCI 1.1 referrers API (falling back to the
``sha256-<hex>`` referrers tag schema when the registry lacks the API), the
cosign ``.att`` and ``.sbom`` tags, and BuildKit attestation manifests inside
the image index. Artifacts are listed, not trusted: nothing here verifies an
attestation's signature.
"""

from __future__ import annotations

from typing import Any

from agent_bom.image_evidence.model import as_dict
from agent_bom.oci_registry.client import RegistryClient, RegistryError, RegistryLimitError
from agent_bom.oci_registry.media_types import (
    COSIGN_SIMPLESIGNING,
    CYCLONEDX_TYPES,
    DOCKER_REFERENCE_DIGEST,
    DSSE_ENVELOPE,
    IN_TOTO,
    SIGSTORE_BUNDLE_PREFIX,
    SPDX_TYPES,
)
from agent_bom.oci_registry.platforms import is_attestation_descriptor
from agent_bom.security import sanitize_text

MAX_REFERRERS = 50
PREDICATE_ANNOTATION = "in-toto.io/predicate-type"


def classify(artifact_type: str, predicate_type: str = "") -> str:
    kind_source = f"{artifact_type} {predicate_type}".lower()
    if artifact_type.startswith(SIGSTORE_BUNDLE_PREFIX) or artifact_type == COSIGN_SIMPLESIGNING:
        return "signature"
    if "spdx" in kind_source or "cyclonedx" in kind_source or artifact_type in SPDX_TYPES | CYCLONEDX_TYPES:
        return "sbom"
    if "slsa" in kind_source or "provenance" in kind_source:
        return "provenance"
    if artifact_type in {IN_TOTO, DSSE_ENVELOPE} or "in-toto" in kind_source or "vulnerability" in kind_source:
        return "attestation"
    return "other"


def _entry(descriptor: dict[str, Any], source: str, subject: str) -> dict[str, Any]:
    annotations = as_dict(descriptor.get("annotations"))
    artifact_type = str(descriptor.get("artifactType") or descriptor.get("mediaType") or "")
    predicate = str(annotations.get(PREDICATE_ANNOTATION) or annotations.get("predicateType") or "")
    return {
        "digest": str(descriptor.get("digest") or ""),
        "artifact_type": sanitize_text(artifact_type, max_len=200),
        "predicate_type": sanitize_text(predicate, max_len=300) or None,
        "kind": classify(artifact_type, predicate),
        "source": source,
        "subject": subject,
    }


def _tag_entries(client: RegistryClient, digest: str, suffix: str, source: str) -> list[dict[str, Any]]:
    manifest = client.get_manifest(digest.replace(":", "-", 1) + suffix, missing_ok=True)
    if manifest is None:
        return []
    if "layers" not in manifest.document and "manifests" not in manifest.document:
        raise RegistryError("Attachment manifest has no descriptor list")
    layers = manifest.document.get("layers") or manifest.document.get("manifests") or []
    return _bounded_entries(layers, source, digest)


def _bounded_entries(descriptors, source: str, subject: str) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            continue
        entry = _entry(descriptor, source, subject)
        unique.setdefault((entry["digest"], entry["source"]), entry)
        if len(unique) > MAX_REFERRERS:
            raise RegistryLimitError("Referrer count limit reached")
    return list(unique.values())


def _referrers_api(client: RegistryClient, digest: str) -> list[dict[str, Any]]:
    listed = client.referrers(digest)
    if listed is not None:
        return _bounded_entries(listed, "referrers-api", digest)
    return _tag_entries(client, digest, "", "referrers-tag-schema")


def _buildkit_attestations(
    client: RegistryClient, index: dict[str, Any] | None, digest: str, limit: int = MAX_REFERRERS
) -> list[dict[str, Any]]:
    if not index:
        return []
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for descriptor in index.get("manifests") or []:
        if not isinstance(descriptor, dict) or not is_attestation_descriptor(descriptor):
            continue
        if descriptor.get("annotations", {}).get(DOCKER_REFERENCE_DIGEST) != digest:
            continue
        manifest_digest = str(descriptor.get("digest") or "")
        if manifest_digest in seen:
            continue
        if len(seen) >= MAX_REFERRERS or len(found) >= limit:
            raise RegistryLimitError("BuildKit attestation count limit reached")
        seen.add(manifest_digest)
        manifest = client.get_manifest(manifest_digest, missing_ok=True)
        if manifest is None or "layers" not in manifest.document:
            raise RegistryError("Attestation manifest is missing or has no layers")
        layers = manifest.document["layers"]
        found.extend(_bounded_entries(layers or [], "buildkit-attestation-manifest", digest))
        if len(found) > limit:
            raise RegistryLimitError("Referrer count limit reached")
    return found


def discover_referrers(client: RegistryClient, digests: list[str], index: dict[str, Any] | None) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for digest in dict.fromkeys(digests):
        for lookup in (
            lambda: _referrers_api(client, digest),
            lambda: _tag_entries(client, digest, ".att", "cosign-attestation-tag"),
            lambda: _tag_entries(client, digest, ".sbom", "cosign-sbom-tag"),
            lambda: _buildkit_attestations(client, index, digest, MAX_REFERRERS - len(unique)),
        ):
            for entry in lookup():
                unique.setdefault((entry["digest"], entry["source"]), entry)
                if len(unique) > MAX_REFERRERS:
                    raise RegistryLimitError("Referrer count limit reached")
    return list(unique.values())
