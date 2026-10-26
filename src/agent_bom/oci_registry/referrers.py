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
from agent_bom.oci_registry.client import RegistryClient
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
    layers = manifest.document.get("layers") or manifest.document.get("manifests") or []
    return [_entry(layer, source, digest) for layer in layers if isinstance(layer, dict)]


def _referrers_api(client: RegistryClient, digest: str) -> list[dict[str, Any]]:
    listed = client.referrers(digest)
    if listed is not None:
        return [_entry(d, "referrers-api", digest) for d in listed]
    return _tag_entries(client, digest, "", "referrers-tag-schema")


def _buildkit_attestations(client: RegistryClient, index: dict[str, Any] | None, digest: str) -> list[dict[str, Any]]:
    if not index:
        return []
    found: list[dict[str, Any]] = []
    for descriptor in index.get("manifests") or []:
        if not isinstance(descriptor, dict) or not is_attestation_descriptor(descriptor):
            continue
        if descriptor.get("annotations", {}).get(DOCKER_REFERENCE_DIGEST) != digest:
            continue
        manifest = client.get_manifest(str(descriptor.get("digest") or ""), missing_ok=True)
        layers = manifest.document.get("layers") if manifest is not None else []
        found.extend(_entry(layer, "buildkit-attestation-manifest", digest) for layer in layers or [] if isinstance(layer, dict))
    return found


def discover_referrers(client: RegistryClient, digests: list[str], index: dict[str, Any] | None) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for digest in digests:
        entries.extend(_referrers_api(client, digest))
        entries.extend(_tag_entries(client, digest, ".att", "cosign-attestation-tag"))
        entries.extend(_tag_entries(client, digest, ".sbom", "cosign-sbom-tag"))
        entries.extend(_buildkit_attestations(client, index, digest))
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in entries:
        unique.setdefault((entry["digest"], entry["source"]), entry)
    return list(unique.values())[:MAX_REFERRERS]
