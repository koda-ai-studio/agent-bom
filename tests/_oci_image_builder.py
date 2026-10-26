"""Build small, real OCI images in memory for parser, registry and evidence tests."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as layer:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            layer.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def dpkg_status(*packages: tuple[str, str]) -> bytes:
    return "".join(f"Package: {name}\nStatus: install ok installed\nVersion: {version}\n\n" for name, version in packages).encode()


@dataclass
class BuiltImage:
    blobs: dict[str, bytes]
    manifest: dict
    manifest_bytes: bytes
    manifest_digest: str
    config: dict
    layer_digests: list[str]
    diff_ids: list[str]
    extra_manifests: dict[str, bytes] = field(default_factory=dict)

    def write_layout(self, root: Path) -> Path:
        blob_dir = root / "blobs" / "sha256"
        blob_dir.mkdir(parents=True, exist_ok=True)
        for digest, data in {**self.blobs, self.manifest_digest: self.manifest_bytes}.items():
            (blob_dir / digest.split(":", 1)[1]).write_bytes(data)
        index = {
            "schemaVersion": 2,
            "manifests": [{"mediaType": OCI_MANIFEST, "digest": self.manifest_digest, "size": len(self.manifest_bytes)}],
        }
        (root / "index.json").write_text(json.dumps(index))
        (root / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
        return root


def build_image(
    layers: list[dict[str, bytes]],
    *,
    env: list[str] | None = None,
    labels: dict[str, str] | None = None,
    history: list[str] | None = None,
    annotations: dict[str, str] | None = None,
    base_layers: list[bytes] | None = None,
) -> BuiltImage:
    """Return an image whose layers hold ``layers`` (path -> bytes), gzip-compressed."""
    raw_layers = list(base_layers or []) + [tar_bytes(files) for files in layers]
    blobs: dict[str, bytes] = {}
    descriptors, diff_ids, layer_digests = [], [], []
    for raw in raw_layers:
        compressed = gzip.compress(raw, mtime=0)
        digest = digest_of(compressed)
        blobs[digest] = compressed
        descriptors.append({"mediaType": LAYER_GZIP, "digest": digest, "size": len(compressed)})
        diff_ids.append(digest_of(raw))
        layer_digests.append(digest)
    steps = history or [f"/bin/sh -c #(nop) ADD file:{index} in /" for index in range(len(raw_layers))]
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Env": env or ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"], "Labels": labels or {}},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "history": [{"created_by": step} for step in steps],
    }
    config_bytes = json.dumps(config).encode()
    config_digest = digest_of(config_bytes)
    blobs[config_digest] = config_bytes
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": config_digest, "size": len(config_bytes)},
        "layers": descriptors,
        **({"annotations": annotations} if annotations else {}),
    }
    manifest_bytes = json.dumps(manifest).encode()
    return BuiltImage(
        blobs=blobs,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_digest=digest_of(manifest_bytes),
        config=config,
        layer_digests=layer_digests,
        diff_ids=diff_ids,
    )


def build_index(platform_images: dict[str, BuiltImage], *, attestation_for: str | None = None) -> tuple[bytes, str]:
    """An OCI index over ``{"linux/amd64": image, ...}``, optionally with a buildx attestation manifest."""
    manifests = []
    for platform, image in platform_images.items():
        os_name, arch, *variant = platform.split("/")
        entry_platform = {"os": os_name, "architecture": arch, **({"variant": variant[0]} if variant else {})}
        manifests.append(
            {"mediaType": OCI_MANIFEST, "digest": image.manifest_digest, "size": len(image.manifest_bytes), "platform": entry_platform}
        )
    if attestation_for:
        target = platform_images[attestation_for]
        manifests.append(
            {
                "mediaType": OCI_MANIFEST,
                "digest": "sha256:" + "e" * 64,
                "size": 10,
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": target.manifest_digest,
                },
            }
        )
    raw = json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests}).encode()
    return raw, digest_of(raw)
