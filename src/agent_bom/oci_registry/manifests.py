"""Resolve an image reference to its platform manifest on a registry."""

from __future__ import annotations

from typing import Any

from agent_bom.image_evidence.model import bounded_string_map
from agent_bom.oci_registry.auth import resolve_credential
from agent_bom.oci_registry.client import FetchedManifest, RegistryClient
from agent_bom.oci_registry.media_types import INDEX_TYPES
from agent_bom.oci_registry.platforms import select_platform
from agent_bom.oci_registry.reference import ImageReference


def open_client(ref: ImageReference, registry_user: str | None = None, registry_pass: str | None = None) -> RegistryClient:
    return RegistryClient(ref, credential_resolver=lambda: resolve_credential(ref, registry_user, registry_pass))


def _is_index(manifest: FetchedManifest) -> bool:
    return manifest.media_type in INDEX_TYPES or ("manifests" in manifest.document and "layers" not in manifest.document)


def index_annotations(index: dict[str, Any], manifest_digest: str) -> dict[str, str]:
    """Index-level annotations plus the chosen platform descriptor's own."""
    merged = bounded_string_map(index.get("annotations"))
    for descriptor in index.get("manifests") or []:
        if isinstance(descriptor, dict) and descriptor.get("digest") == manifest_digest:
            merged.update(bounded_string_map(descriptor.get("annotations")))
    return merged


def resolve_image_manifest(
    client: RegistryClient, ref: ImageReference, platform: str | None
) -> tuple[FetchedManifest, FetchedManifest | None, str | None, list[str]]:
    """Return ``(manifest, index, platform, available_platforms)`` for ``ref``."""
    top = client.get_manifest(ref.manifest_ref)
    assert top is not None
    if not _is_index(top):
        return top, None, None, []
    descriptor, chosen, available = select_platform(top.document, platform)
    manifest = client.get_manifest(str(descriptor.get("digest") or ""))
    assert manifest is not None
    return manifest, top, chosen, available
