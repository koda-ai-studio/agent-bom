"""Container image reference helpers shared by producers and the graph."""

from __future__ import annotations

DIGEST_PREFIX = "sha256:"


def image_repository(ref: str) -> str:
    """``registry/repo`` without tag or digest."""
    base = ref.split("@", 1)[0]
    slash, colon = base.rfind("/"), base.rfind(":")
    return base[:colon] if colon > slash else base


def digest_in_ref(ref: str) -> str:
    """The ``sha256:`` digest a reference pins, or ``""``."""
    tail = ref.rsplit("@", 1)[1] if "@" in ref else ""
    return tail if tail.startswith(DIGEST_PREFIX) else ""


def image_key(ref: str, digest: str = "") -> str:
    """``repo@digest`` when a digest is known, else the reference as written."""
    digest = digest if digest.startswith(DIGEST_PREFIX) else digest_in_ref(ref)
    return f"{image_repository(ref)}@{digest}" if digest else ref.strip()
