"""Package carriers for scanned images, image archives, filesystems and host OS packages.

A carrier is the ``Agent`` + one ``MCPServer`` shape that transports scanned
packages through the agent pipeline. Every scan surface (CLI, API, MCP) builds
carriers here so the same input always yields the same agent and server ids
and the same graph image node.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_bom.image_evidence import ImageEvidence, collect_image_evidence
from agent_bom.image_evidence.surfaces import image_agent_metadata
from agent_bom.models import Agent, AgentType, MCPServer, Package, ServerSurface, TransportType
from agent_bom.parsers.oci_model_artifacts import collect_model_artifacts, model_artifact_metadata

IMAGE_INVENTORY_ROLE = "container_image"


def build_image_carrier(
    image_ref: str,
    packages: list[Package],
    *,
    source: str = "image",
    digest: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> Agent:
    """The carrier for an image scanned by reference (``--image``, ``--k8s``, MCP ``image``, API ``images``)."""
    server = MCPServer(
        name=image_ref,
        command="docker",
        args=["run", image_ref],
        transport=TransportType.STDIO,
        packages=packages,
        surface=ServerSurface.CONTAINER_IMAGE,
    )
    return Agent(
        name=f"image:{image_ref}",
        agent_type=AgentType.CUSTOM,
        config_path=f"docker://{image_ref}",
        source=source or "image",
        metadata={"inventory_role": IMAGE_INVENTORY_ROLE, "image_ref": image_ref, "image_digest": digest, **(metadata or {})},
        mcp_servers=[server],
    )


def build_image_tar_carrier(tar_path: str, packages: list[Package], *, metadata: Mapping[str, Any] | None = None) -> Agent:
    """The carrier for an OCI/Docker image archive (``--image-tar``)."""
    label = Path(tar_path).name
    server = MCPServer(name=label, command="", args=[], transport=TransportType.STDIO, packages=packages, surface=ServerSurface.OCI_TARBALL)
    return Agent(
        name=f"image-tar:{label}",
        agent_type=AgentType.CUSTOM,
        config_path=f"oci-tar://{tar_path}",
        source="image-tar",
        metadata={"inventory_role": IMAGE_INVENTORY_ROLE, "image_ref": label, **(metadata or {})},
        mcp_servers=[server],
    )


def build_filesystem_carrier(fs_path: str, packages: list[Package]) -> Agent:
    """The carrier for a mounted filesystem or disk snapshot (``--filesystem``)."""
    server = MCPServer(name=f"fs:{fs_path}", surface=ServerSurface.FILESYSTEM)
    server.packages = packages
    return Agent(
        name=f"filesystem:{Path(fs_path).name}",
        agent_type=AgentType.CUSTOM,
        config_path=fs_path,
        source="filesystem",
        mcp_servers=[server],
    )


def build_os_packages_carrier(packages: list[Package]) -> Agent:
    """The carrier for the host's own OS packages (``--os-packages``)."""
    server = MCPServer(name="os-packages", surface=ServerSurface.OS_PACKAGES)
    server.packages = packages
    return Agent(name="os-packages", agent_type=AgentType.CUSTOM, config_path="/", source="os-packages", mcp_servers=[server])


@dataclass
class ImageScan:
    """One image scanned by reference: its carrier plus what the scan observed."""

    carrier: Agent
    evidence: ImageEvidence
    strategy: str

    @property
    def packages(self) -> list[Package]:
        return self.carrier.mcp_servers[0].packages


@contextmanager
def _evidence(image_ref: str, cosign_key_path: str | None) -> Iterator[tuple[ImageEvidence, Any]]:
    with collect_image_evidence(image_ref, cosign_key_path=cosign_key_path) as evidence, collect_model_artifacts(image_ref) as models:
        yield evidence, models


def scan_image_carrier(
    image_ref: str,
    *,
    source: str = "image",
    digest: str = "",
    cosign_key_path: str | None = None,
    **scan_kwargs: Any,
) -> ImageScan:
    """Scan ``image_ref`` and build its carrier with image evidence and model-artifact metadata.

    ``scan_kwargs`` go to :func:`agent_bom.image.scan_image`; its ``ImageScanError`` propagates.
    """
    from agent_bom.image import scan_image

    with _evidence(image_ref, cosign_key_path) as (evidence, models):
        packages, strategy = scan_image(image_ref, **scan_kwargs)
    metadata = {**image_agent_metadata(evidence), **model_artifact_metadata(models)}
    carrier = build_image_carrier(image_ref, packages, source=source, digest=evidence.digest or digest, metadata=metadata)
    return ImageScan(carrier=carrier, evidence=evidence, strategy=strategy)
