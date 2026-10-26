"""Base-image identification and base-vs-app attribution of image packages.

The base is named only from explicit evidence: the OCI
``org.opencontainers.image.base.name`` / ``.base.digest`` keys on the manifest
annotations or the config labels. Layers are attributed to the base only when
the base's own layer list (``rootfs.diff_ids``) is an exact prefix of the
image's — a base named but not layer-matched stays ``unresolved`` and no
package is attributed.
"""

from __future__ import annotations

from typing import Any

from agent_bom.image_evidence.model import ImageEvidence
from agent_bom.security import sanitize_text

BASE_NAME_KEY = "org.opencontainers.image.base.name"
BASE_DIGEST_KEY = "org.opencontainers.image.base.digest"


def identify_base_image(evidence: ImageEvidence) -> dict[str, Any] | None:
    """Base image named by annotations (preferred) or labels; ``None`` when neither names one."""
    for source, values in (("manifest-annotation", evidence.annotations), ("config-label", evidence.labels)):
        name, digest = values.get(BASE_NAME_KEY), values.get(BASE_DIGEST_KEY)
        if name or digest:
            return {
                "name": sanitize_text(name, max_len=300) if name else None,
                "digest": digest if isinstance(digest, str) and digest.startswith("sha256:") else None,
                "source": source,
                "attribution": "unresolved",
                "layer_count": None,
            }
    return None


def match_base_layers(evidence: ImageEvidence, base_diff_ids: list[str]) -> None:
    """Attribute the image's lowest layers to the base when the base's layers are an exact prefix."""
    base = evidence.base_image
    if base is None:
        return
    count = len(base_diff_ids)
    if count and len(evidence.diff_ids) >= count and evidence.diff_ids[:count] == base_diff_ids:
        base["attribution"] = "layer-digest-match"
        base["layer_count"] = count
    else:
        base["attribution"] = "layer-digest-mismatch"
        base["layer_count"] = None


def attribute_packages(evidence: ImageEvidence, packages: list[Any]) -> None:
    """Stamp ``layer_origin`` (``base``/``app``) on package occurrences and summarize the split."""
    base = evidence.base_image
    if base is None or not isinstance(base.get("layer_count"), int):
        return
    boundary = int(base["layer_count"])
    from_base = from_app = 0
    for package in packages:
        occurrences = getattr(package, "occurrences", None) or []
        if not occurrences:
            continue
        for occurrence in occurrences:
            occurrence.layer_origin = "base" if occurrence.layer_index <= boundary else "app"
            occurrence.base_image = base.get("name") if occurrence.layer_origin == "base" else None
        # A version upgrade in an app layer clears the older occurrences, so any surviving
        # base-layer occurrence means the base shipped exactly this version.
        if any(occurrence.layer_origin == "base" for occurrence in occurrences):
            from_base += 1
        else:
            from_app += 1
    base["packages_from_base"] = from_base
    base["packages_from_app"] = from_app
