"""Record an image's manifest/config facts into the active evidence collector."""

from __future__ import annotations

import re
from typing import Any

from agent_bom.image_evidence.base_image import identify_base_image
from agent_bom.image_evidence.config_secrets import scan_config_secrets, scan_string_map
from agent_bom.image_evidence.model import active_image_evidence, as_dict, as_list

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
    index_annotations: dict[str, Any] | None = None,
) -> None:
    """Capture digests, labels, annotations, config secrets and the named base image.

    Labels and annotations are author-controlled text: secrets in them are
    redacted in the evidence and reported like config ``ENV`` secrets.
    """
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
    evidence.labels, label_secrets = scan_string_map(_labels(config), "config_label", "label")
    raw_annotations = {**as_dict(index_annotations), **as_dict(manifest.get("annotations") if manifest is not None else None)}
    annotations, annotation_secrets = scan_string_map(raw_annotations, "annotation", "annotation")
    evidence.annotations = {**evidence.annotations, **annotations}
    secrets = [*scan_config_secrets(config), *label_secrets, *annotation_secrets]
    evidence.config_secrets = [{**secret, "image": evidence.reference} for secret in secrets]
    evidence.base_image = evidence.base_image or identify_base_image(evidence)
