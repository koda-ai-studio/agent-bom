"""Parse an image reference into the registry host, repository and tag/digest.

Follows the distribution reference grammar: a first path component holding a
``.`` or ``:`` (or equal to ``localhost``) names the registry; anything else is
a Docker Hub repository, where one-component names live under ``library/``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DOCKER_HUB_API = "registry-1.docker.io"
DOCKER_HUB_ALIASES = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"})
_DOCKER_HUB_LEGACY_KEY = "https://index.docker.io/v1/"
_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$|^sha512:[a-f0-9]{128}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]"})
_MAX_NAME_LENGTH = 255


class ReferenceError(ValueError):
    """The image reference is not a valid distribution reference."""


@dataclass(frozen=True)
class ImageReference:
    """One image addressed on a registry."""

    registry: str
    repository: str
    tag: str | None
    digest: str | None
    original: str

    @property
    def manifest_ref(self) -> str:
        """Digest when pinned, otherwise the tag — what ``/manifests/<ref>`` takes."""
        return self.digest or self.tag or "latest"

    @property
    def is_docker_hub(self) -> bool:
        return self.registry == DOCKER_HUB_API

    @property
    def allows_plain_http(self) -> bool:
        """Plain HTTP is accepted only for a registry on the loopback interface."""
        return self.registry.rsplit(":", 1)[0] in _LOOPBACK_HOSTS

    @property
    def display(self) -> str:
        suffix = f":{self.tag}" if self.tag else ""
        return f"{self.registry}/{self.repository}{suffix}" + (f"@{self.digest}" if self.digest else "")

    def credential_keys(self) -> list[str]:
        """Keys that ``~/.docker/config.json`` may file this registry's credentials under."""
        if self.is_docker_hub:
            return [_DOCKER_HUB_LEGACY_KEY, "docker.io", "index.docker.io", DOCKER_HUB_API]
        return [self.registry, f"https://{self.registry}", f"http://{self.registry}"]


def _split_digest(raw: str) -> tuple[str, str | None]:
    if "@" not in raw:
        return raw, None
    name, digest = raw.split("@", 1)
    if not _DIGEST_RE.match(digest):
        raise ReferenceError(f"Invalid digest in image reference: {raw!r}")
    return name, digest


def _split_tag(name: str) -> tuple[str, str | None]:
    last = name.rsplit("/", 1)[-1]
    if ":" not in last:
        return name, None
    head, tag = name.rsplit(":", 1)
    if not _TAG_RE.match(tag):
        raise ReferenceError(f"Invalid tag in image reference: {tag!r}")
    return head, tag


def _split_registry(name: str) -> tuple[str, str]:
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        if not _HOST_RE.match(first):
            raise ReferenceError(f"Invalid registry host: {first!r}")
        registry = DOCKER_HUB_API if first.lower() in DOCKER_HUB_ALIASES else first.lower()
        return registry, rest
    return DOCKER_HUB_API, name


def parse_reference(raw: str) -> ImageReference:
    """Parse ``raw`` into an :class:`ImageReference`; raise :class:`ReferenceError` if malformed."""
    text = (raw or "").strip()
    if not text or text.startswith("-") or len(text) > _MAX_NAME_LENGTH + 140:
        raise ReferenceError(f"Invalid image reference: {raw!r}")
    name, digest = _split_digest(text)
    name, tag = _split_tag(name)
    registry, repository = _split_registry(name)
    if registry == DOCKER_HUB_API and "/" not in repository:
        repository = f"library/{repository}"
    components = repository.split("/")
    if len(repository) > _MAX_NAME_LENGTH or not all(_COMPONENT_RE.match(part) for part in components):
        raise ReferenceError(f"Invalid repository in image reference: {raw!r}")
    if tag is None and digest is None:
        tag = "latest"
    return ImageReference(registry=registry, repository=repository, tag=tag, digest=digest, original=text)
