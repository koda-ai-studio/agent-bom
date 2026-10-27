"""Container image reference helpers shared by producers and the graph.

One parser for ``[registry/]path[:tag][@digest]`` so every producer names the
same image the same way. The registry rule is the docker CLI's: the first
path segment is a registry host when it contains ``.`` or ``:`` or is
``localhost``; otherwise the image lives on Docker Hub, where a single-segment
path is an official ``library/`` image.
"""

from __future__ import annotations

from dataclasses import dataclass

DIGEST_PREFIX = "sha256:"
DOCKER_HUB = "docker.io"


@dataclass(frozen=True)
class ImageReference:
    name: str
    """The reference as written, without tag or digest."""
    registry: str
    path: str
    """Repository path inside the registry (``library/<name>`` for official Docker Hub images)."""
    tag: str
    digest: str

    @property
    def version(self) -> str:
        """What the reference pins: the digest, else the tag, else ``latest``."""
        return self.digest or self.tag or "latest"


def _is_registry_host(segment: str) -> bool:
    return "." in segment or ":" in segment or segment == "localhost"


def parse_image_ref(ref: str) -> ImageReference:
    base, _, tail = ref.strip().partition("@")
    digest = tail if ":" in tail else ""
    slash, colon = base.rfind("/"), base.rfind(":")
    name, tag = (base[:colon], base[colon + 1 :]) if colon > slash else (base, "")
    first, _, rest = name.partition("/")
    if rest and _is_registry_host(first):
        registry, path = first, rest
    else:
        registry, path = DOCKER_HUB, name
    if registry == DOCKER_HUB and path and "/" not in path:
        path = f"library/{path}"
    return ImageReference(name=name, registry=registry, path=path, tag=tag, digest=digest)


def image_repository(ref: str) -> str:
    """``registry/repo`` without tag or digest."""
    return parse_image_ref(ref).name


def digest_in_ref(ref: str) -> str:
    """The digest a reference pins, or ``""``."""
    return parse_image_ref(ref).digest


def image_key(ref: str, digest: str = "") -> str:
    """``repo@digest`` when a digest is known, else the reference as written."""
    digest = digest if digest.startswith(DIGEST_PREFIX) else digest_in_ref(ref)
    return f"{image_repository(ref)}@{digest}" if digest else ref.strip()
