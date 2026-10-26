"""Bounded scan of a flattened container filesystem (``docker export``).

An exported root filesystem is one very large layer. It goes through the same
walk as ``scan_oci`` layers: read in place without buffering, with the
member-count, size and wall-clock limits, and with every limit it crosses
recorded as a coverage gap so the scan reports as partial.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.coverage import record_scan_input_warning
from agent_bom.models import Package
from agent_bom.oci_parser import LayerMetadata, _ImageWalk

ROOTFS_LAYER_PATH = "docker-export"


def scan_rootfs_tar(path: Path) -> list[Package]:
    """Extract packages from an uncompressed root-filesystem tar under the image scan bounds."""
    walk = _ImageWalk(None)
    layer = LayerMetadata(layer_index=1, layer_id=ROOTFS_LAYER_PATH, layer_path=ROOTFS_LAYER_PATH)
    with path.open("rb") as source:
        walk.scan(ROOTFS_LAYER_PATH, layer, source, path.stat().st_size)
    packages = walk.finish()
    for warning in walk.coverage_warnings:
        record_scan_input_warning(scanner="oci", path=warning.path, reason=warning.reason, detail=warning.detail)
    return packages
