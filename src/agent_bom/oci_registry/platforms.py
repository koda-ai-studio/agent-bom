"""Choose one platform manifest from an image index."""

from __future__ import annotations

from typing import Any

from agent_bom.oci_registry.media_types import DOCKER_ATTESTATION_MANIFEST, DOCKER_REFERENCE_TYPE

DEFAULT_PLATFORM = "linux/amd64"


class PlatformNotFoundError(Exception):
    """The index lists no manifest for the requested platform."""

    def __init__(self, wanted: str, available: list[str]) -> None:
        listed = ", ".join(available) or "none"
        super().__init__(f"Image has no {wanted} manifest (available: {listed}); pass --platform to choose one")
        self.available = available


def platform_string(descriptor: dict[str, Any]) -> str | None:
    platform = descriptor.get("platform")
    if not isinstance(platform, dict):
        return None
    os_name, arch = platform.get("os"), platform.get("architecture")
    if not os_name or not arch or os_name == "unknown":
        return None
    variant = platform.get("variant")
    return f"{os_name}/{arch}/{variant}" if variant else f"{os_name}/{arch}"


def is_attestation_descriptor(descriptor: dict[str, Any]) -> bool:
    annotations = descriptor.get("annotations")
    return isinstance(annotations, dict) and annotations.get(DOCKER_REFERENCE_TYPE) == DOCKER_ATTESTATION_MANIFEST


def image_descriptors(index: dict[str, Any]) -> list[dict[str, Any]]:
    """Runnable image manifests in an index (attestation manifests excluded)."""
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        return []
    return [m for m in manifests if isinstance(m, dict) and not is_attestation_descriptor(m) and platform_string(m)]


def _matches(candidate: str, wanted: str) -> bool:
    if candidate == wanted:
        return True
    # ``linux/arm64`` also selects ``linux/arm64/v8``; an explicit variant must match exactly.
    return wanted.count("/") == 1 and candidate.startswith(wanted + "/")


def select_platform(index: dict[str, Any], wanted: str | None) -> tuple[dict[str, Any], str, list[str]]:
    """Return ``(descriptor, platform, available)`` for ``wanted`` (default ``linux/amd64``)."""
    target = wanted or DEFAULT_PLATFORM
    descriptors = image_descriptors(index)
    available = [p for d in descriptors if (p := platform_string(d))]
    for descriptor in descriptors:
        platform = platform_string(descriptor)
        if platform and _matches(platform, target):
            return descriptor, platform, available
    raise PlatformNotFoundError(target, available)
