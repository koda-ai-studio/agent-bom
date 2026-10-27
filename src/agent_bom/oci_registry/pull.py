"""Daemonless image scan: pull manifest, config and layers over the distribution API.

Layers stream one at a time into a private temporary file (digest-verified,
capped at the compressed-layer limit) and go through the same bounded walk as
``docker save`` archives — member-count, size, decompression-ratio and
wall-clock limits apply, and every limit crossed is a recorded coverage gap.
"""

from __future__ import annotations

import tempfile
from typing import Any

from agent_bom.coverage import record_scan_input_warning
from agent_bom.image_evidence.model import ImageEvidence, active_image_evidence
from agent_bom.image_evidence.record import record_image_config
from agent_bom.models import Package
from agent_bom.oci_parser import _ImageWalk
from agent_bom.oci_registry.client import RegistryClient, RegistryError
from agent_bom.oci_registry.manifests import index_annotations, open_client, resolve_image_manifest
from agent_bom.oci_registry.media_types import MANIFEST_TYPES, READABLE_LAYER_TYPES, ZSTD_LAYER_TYPES
from agent_bom.oci_registry.platforms import PlatformNotFoundError
from agent_bom.oci_registry.policy import LOCAL_POLICY, RegistryPolicy
from agent_bom.oci_registry.reference import parse_reference
from agent_bom.oci_registry.supply_chain import discover_supply_chain
from agent_bom.oci_registry.validation import validate_image_config
from agent_bom.parsers.oci_io import _max_json_member_bytes, _max_layer_compressed_bytes
from agent_bom.parsers.oci_metadata import _build_layer_metadata
from agent_bom.parsers.oci_stream import LayerLimitError


def _config_platform(config: dict[str, Any]) -> str | None:
    os_name, arch = config.get("os"), config.get("architecture")
    if not os_name or not arch:
        return None
    variant = config.get("variant")
    return f"{os_name}/{arch}/{variant}" if variant else f"{os_name}/{arch}"


def _scan_layers(
    client: RegistryClient,
    manifest: dict[str, Any],
    config: dict[str, Any],
    evidence: ImageEvidence | None,
    annotations: dict[str, Any] | None = None,
) -> list[Package]:
    descriptors = [d for d in manifest.get("layers", []) if isinstance(d, dict)]
    layer_paths = [f"blobs/sha256/{str(d.get('digest', '')).removeprefix('sha256:')}" for d in descriptors]
    config_ref = str(manifest.get("config", {}).get("digest") or "")
    record_image_config(config, layer_paths, manifest=manifest, config_ref=config_ref, index_annotations=annotations)
    walk = _ImageWalk(config)
    for descriptor, layer_path, layer in zip(descriptors, layer_paths, _build_layer_metadata(layer_paths, config), strict=False):
        media_type, digest = str(descriptor.get("mediaType") or ""), str(descriptor.get("digest") or "")
        declared = int(descriptor.get("size") or 0)
        if media_type in ZSTD_LAYER_TYPES or (media_type and media_type not in READABLE_LAYER_TYPES):
            walk.gap(
                layer_path,
                "oci_layer_unsupported_media_type",
                f"Layer media type {media_type} is not readable; image inventory is incomplete.",
            )
            continue
        limit = _max_layer_compressed_bytes()
        if declared > limit:
            walk.gap(
                layer_path,
                "oci_layer_size_limit",
                "Container layer exceeds the compressed-size safety limit; image inventory is incomplete.",
            )
            continue
        with tempfile.TemporaryFile() as spool:
            try:
                size = client.fetch_blob(digest, spool, limit, on_chunk=lambda _n: walk.budget.check())
            except LayerLimitError as exc:
                walk.gap(layer_path, exc.reason, exc.detail)
                continue
            except RegistryError as exc:
                walk.gap(
                    layer_path,
                    "oci_layer_download_failed",
                    f"Container layer could not be downloaded ({exc}); image inventory is incomplete.",
                )
                continue
            spool.seek(0)
            walk.scan(layer_path, layer, spool, size)
    packages = walk.finish()
    for warning in walk.coverage_warnings:
        record_scan_input_warning(scanner="oci", path=warning.path, reason=warning.reason, detail=warning.detail)
        if evidence is not None:
            evidence.note(f"{warning.path}: {warning.detail}")
    return packages


def scan_registry_image(
    image_ref: str,
    *,
    platform: str | None = None,
    registry_user: str | None = None,
    registry_pass: str | None = None,
    policy: RegistryPolicy = LOCAL_POLICY,
) -> list[Package]:
    """Scan ``image_ref`` straight from its registry; raise ``RegistryError``/``PlatformNotFoundError`` on failure."""
    ref = parse_reference(image_ref)
    evidence = active_image_evidence()
    with open_client(ref, registry_user, registry_pass, policy=policy) as client:
        manifest, index, chosen, available = resolve_image_manifest(client, ref, platform)
        if manifest.media_type not in MANIFEST_TYPES and "layers" not in manifest.document:
            raise RegistryError(f"Unsupported manifest media type: {manifest.media_type or 'unknown'}")
        if "config" not in manifest.document or "layers" not in manifest.document:
            raise RegistryError("Image manifest has invalid or missing config/layers")
        config_digest = str(manifest.document["config"]["digest"])
        config = client.fetch_json_blob(config_digest, _max_json_member_bytes())
        try:
            validate_image_config(config)
        except ValueError as exc:
            raise RegistryError("Image config contains invalid metadata") from exc
        actual = chosen or _config_platform(config)
        if index is None and platform and actual and not actual.startswith(platform):
            raise PlatformNotFoundError(platform, [actual])
        if evidence is not None:
            evidence.source = "registry"
            evidence.registry, evidence.repository = ref.registry, ref.repository
            evidence.digest, evidence.index_digest = manifest.digest, index.digest if index else None
            evidence.platform, evidence.available_platforms = actual, available
            evidence.config_digest = config_digest
        annotations = index_annotations(index.document, manifest.digest) if index is not None else None
        packages = _scan_layers(client, manifest.document, config, evidence, annotations)
        if evidence is not None:
            evidence.credential_source = client.credential_source
            discover_supply_chain(client, evidence, index.document if index else None)
    return packages


__all__ = ["open_client", "resolve_image_manifest", "scan_registry_image"]
