"""Validate registry JSON before interpreting it as scan or trust evidence."""

from __future__ import annotations

from typing import Any

from agent_bom.core.image_ref import is_image_digest


def _string_map(value: Any) -> bool:
    return isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())


def validate_descriptor(value: Any) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("digest"), str) or not is_image_digest(value["digest"]):
        raise ValueError("Registry descriptor has an invalid digest")
    for field in ("mediaType", "artifactType"):
        if field in value and not isinstance(value[field], str):
            raise ValueError("Registry descriptor has an invalid media type")
    if "size" in value and (type(value["size"]) is not int or value["size"] < 0):
        raise ValueError("Registry descriptor has an invalid size")
    if "annotations" in value and not _string_map(value["annotations"]):
        raise ValueError("Registry descriptor has invalid annotations")
    platform = value.get("platform")
    if platform is not None and (
        not isinstance(platform, dict) or any(not isinstance(platform.get(k, ""), str) for k in ("os", "architecture", "variant"))
    ):
        raise ValueError("Registry descriptor has an invalid platform")


def validate_manifest(document: dict[str, Any]) -> None:
    for field in ("layers", "manifests"):
        if field not in document:
            continue
        if not isinstance(document[field], list):
            raise ValueError("Registry manifest has an invalid descriptor list")
        for descriptor in document[field]:
            validate_descriptor(descriptor)
    if "config" in document:
        validate_descriptor(document["config"])
    if "annotations" in document and not _string_map(document["annotations"]):
        raise ValueError("Registry manifest has invalid annotations")


def validate_image_config(config: dict[str, Any]) -> None:
    history = config.get("history", [])
    if not isinstance(history, list) or any(not isinstance(entry, dict) for entry in history):
        raise ValueError("Image config has invalid history")
    for entry in history:
        if "created_by" in entry and not isinstance(entry["created_by"], str):
            raise ValueError("Image config has invalid history text")
        if "empty_layer" in entry and not isinstance(entry["empty_layer"], bool):
            raise ValueError("Image config has invalid empty-layer marker")
    for field in ("os", "architecture", "variant"):
        if field in config and not isinstance(config[field], str):
            raise ValueError("Image config has an invalid platform")
    rootfs = config.get("rootfs", {})
    if not isinstance(rootfs, dict) or not isinstance(rootfs.get("diff_ids", []), list):
        raise ValueError("Image config has invalid filesystem metadata")
    if any(not isinstance(d, str) or not is_image_digest(d) for d in rootfs.get("diff_ids", [])):
        raise ValueError("Image config has invalid filesystem digests")
    for field in ("config", "Config"):
        block = config.get(field)
        if block is None:
            continue
        if not isinstance(block, dict):
            raise ValueError("Image config has an invalid runtime config")
        env = block.get("Env")
        if env is not None and (not isinstance(env, list) or any(not isinstance(e, str) for e in env)):
            raise ValueError("Image config has invalid environment entries")
        if block.get("Labels") is not None and not _string_map(block["Labels"]):
            raise ValueError("Image config has invalid labels")
