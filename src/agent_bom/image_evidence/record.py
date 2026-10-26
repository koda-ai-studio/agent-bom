"""Record an image's manifest/config facts into the active evidence collector."""

from __future__ import annotations

import re
from typing import Any

from agent_bom.image_evidence.base_image import identify_base_image
from agent_bom.image_evidence.config_secrets import scan_config_secrets
from agent_bom.image_evidence.model import active_image_evidence, as_dict, as_list, bounded_string_map

_HEX_RE = re.compile(r"(?:^|/)(?:sha256/)?([a-f0-9]{64})(?:\.json)?$")


def _digest_from_path(path: str) -> str | None:
    match = _HEX_RE.search(path or "")
    return f"sha256:{match.group(1)}" if match else None


def _labels(config: dict[str, Any]) -> object:
    block = config.get("config") or config.get("Config") or {}
    return block.get("Labels") if isinstance(block, dict) else None


def record_image_config(
    config: dict[str, Any] | None,
    layer_paths: list[str],
    *,
    manifest: dict[str, Any] | None = None,
    config_ref: str | None = None,
    source: str | None = None,
) -> None:
    """Capture digests, labels, annotations, config secrets and the named base image."""
    evidence = active_image_evidence()
    if evidence is None:
        return
    if source and evidence.source == "unknown":
        evidence.source = source
    config = config if isinstance(config, dict) else {}
    evidence.config_digest = evidence.config_digest or _digest_from_path(config_ref or "")
    evidence.diff_ids = [d for d in as_list(as_dict(config.get("rootfs")).get("diff_ids")) if isinstance(d, str)]
    blob_digests = [_digest_from_path(path) for path in layer_paths if path.startswith(("blobs/", "./blobs/"))]
    if blob_digests and len(blob_digests) == len(layer_paths) and all(blob_digests):
        evidence.layer_digests = [d for d in blob_digests if d]
    evidence.labels = bounded_string_map(_labels(config))
    if manifest is not None:
        evidence.annotations = {**evidence.annotations, **bounded_string_map(manifest.get("annotations"))}
    evidence.config_secrets = [{**secret, "image": evidence.reference} for secret in scan_config_secrets(config)]
    evidence.base_image = evidence.base_image or identify_base_image(evidence)
