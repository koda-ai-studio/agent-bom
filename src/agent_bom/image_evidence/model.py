"""Per-image evidence collected while one image is scanned.

A caller opens :func:`collect_image_evidence` around ``scan_image`` /
``scan_image_tar``; the scan paths (registry pull, daemon save, archive parse)
and the layer secret stage record into the active collector. Without an
active collector every recorder is a no-op, so plain package scans pay
nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_text

SIGNATURE_STATUSES = ("verified", "invalid", "signed", "unsigned", "unknown")
MAX_LABELS = 64
MAX_LAYER_SECRETS = 200

_ACTIVE: ContextVar[ImageEvidence | None] = ContextVar("image_evidence", default=None)


@dataclass
class SecretScanStats:
    files_scanned: int = 0
    skipped_large: int = 0
    skipped_binary: int = 0
    capped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "skipped_large": self.skipped_large,
            "skipped_binary": self.skipped_binary,
            "capped": self.capped,
            "complete": not self.capped,
        }


@dataclass
class ImageEvidence:
    """What one image scan established beyond its package inventory."""

    reference: str
    source: str = "unknown"
    registry: str | None = None
    repository: str | None = None
    digest: str | None = None
    index_digest: str | None = None
    platform: str | None = None
    available_platforms: list[str] = field(default_factory=list)
    config_digest: str | None = None
    layer_digests: list[str] = field(default_factory=list)
    diff_ids: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    signature: dict[str, Any] = field(default_factory=lambda: {"status": "unknown", "detail": "Signature lookup was not performed."})
    referrers: list[dict[str, Any]] = field(default_factory=list)
    base_image: dict[str, Any] | None = None
    layer_secrets: list[dict[str, Any]] = field(default_factory=list)
    config_secrets: list[dict[str, Any]] = field(default_factory=list)
    secret_scan: SecretScanStats = field(default_factory=SecretScanStats)
    notes: list[str] = field(default_factory=list)
    credential_source: str | None = None
    cosign_key_path: str | None = field(default=None, repr=False)

    def restart(self) -> None:
        """Drop what a failed attempt recorded before another strategy scans the image (notes stay)."""
        fresh = ImageEvidence(reference=self.reference, cosign_key_path=self.cosign_key_path, notes=self.notes)
        self.__dict__.update(fresh.__dict__)

    def layer_digest(self, layer_index: int) -> str | None:
        """Digest of the 1-based layer: the blob digest when known, else the diff id."""
        for digests in (self.layer_digests, self.diff_ids):
            if 0 < layer_index <= len(digests):
                return digests[layer_index - 1]
        return None

    def add_layer_secret(self, secret: dict[str, Any]) -> None:
        if len(self.layer_secrets) >= MAX_LAYER_SECRETS:
            self.secret_scan.capped = True
            return
        self.layer_secrets.append(secret)

    def note(self, message: str) -> None:
        text = sanitize_text(message, max_len=300)
        if text not in self.notes:
            self.notes.append(text)

    def to_metadata(self) -> dict[str, Any]:
        """JSON-safe summary for ``Agent.metadata['image']``; never carries secret values."""
        return {
            "reference": sanitize_text(self.reference, max_len=300),
            "source": self.source,
            "registry": self.registry,
            "repository": self.repository,
            "digest": self.digest,
            "index_digest": self.index_digest,
            "platform": self.platform,
            "available_platforms": list(self.available_platforms),
            "config_digest": self.config_digest,
            "layer_count": len(self.layer_digests or self.diff_ids),
            "layer_digests": list(self.layer_digests),
            "diff_ids": list(self.diff_ids),
            "labels": dict(self.labels),
            "annotations": dict(self.annotations),
            "signature": dict(self.signature),
            "referrers": [dict(item) for item in self.referrers],
            "base_image": dict(self.base_image) if self.base_image else None,
            "secrets": [dict(item) for item in (*self.config_secrets, *self.layer_secrets)],
            "secret_scan": self.secret_scan.to_dict(),
            "notes": list(self.notes),
            "credential_source": self.credential_source,
        }


@contextmanager
def collect_image_evidence(reference: str, *, cosign_key_path: str | None = None) -> Iterator[ImageEvidence]:
    """Collect evidence for one image scan; the cosign key defaults to ``AGENT_BOM_IMAGE_COSIGN_KEY``."""
    key = cosign_key_path or env_raw("AGENT_BOM_IMAGE_COSIGN_KEY") or None
    evidence = ImageEvidence(reference=reference, cosign_key_path=key)
    token = _ACTIVE.set(evidence)
    try:
        yield evidence
    finally:
        _ACTIVE.reset(token)


def active_image_evidence() -> ImageEvidence | None:
    return _ACTIVE.get()


def as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def bounded_string_map(raw: object) -> dict[str, str]:
    """Labels/annotations as a bounded, sanitized ``str -> str`` map."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key in sorted(raw, key=str)[:MAX_LABELS]:
        value = raw[key]
        if isinstance(value, (str, int, float, bool)):
            out[sanitize_text(str(key), max_len=200)] = sanitize_text(str(value), max_len=500)
    return out
