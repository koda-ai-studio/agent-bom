"""OCI and Docker distribution media types the registry client understands."""

from __future__ import annotations

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"

INDEX_TYPES = frozenset({OCI_INDEX, DOCKER_MANIFEST_LIST})
MANIFEST_TYPES = frozenset({OCI_MANIFEST, DOCKER_MANIFEST})
MANIFEST_ACCEPT = ", ".join((OCI_INDEX, DOCKER_MANIFEST_LIST, OCI_MANIFEST, DOCKER_MANIFEST))

# Layer media types the bounded walk can read (gzip, plain tar; zstd is not).
READABLE_LAYER_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
    }
)
ZSTD_LAYER_TYPES = frozenset({"application/vnd.oci.image.layer.v1.tar+zstd"})

COSIGN_SIMPLESIGNING = "application/vnd.dev.cosign.simplesigning.v1+json"
SIGSTORE_BUNDLE_PREFIX = "application/vnd.dev.sigstore.bundle"
IN_TOTO = "application/vnd.in-toto+json"
DSSE_ENVELOPE = "application/vnd.dsse.envelope.v1+json"
SPDX_TYPES = frozenset({"application/spdx+json", "text/spdx", "application/vnd.spdx+json"})
CYCLONEDX_TYPES = frozenset({"application/vnd.cyclonedx+json", "application/vnd.cyclonedx+xml", "application/vnd.cyclonedx"})

DOCKER_REFERENCE_TYPE = "vnd.docker.reference.type"
DOCKER_REFERENCE_DIGEST = "vnd.docker.reference.digest"
DOCKER_ATTESTATION_MANIFEST = "attestation-manifest"
