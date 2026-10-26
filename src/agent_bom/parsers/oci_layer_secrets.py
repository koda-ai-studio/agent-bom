"""Hardcoded secrets inside container image layers.

Runs only while an :func:`agent_bom.image_evidence.collect_image_evidence`
collector is active. Each layer member that the filesystem secret scanner
would open (same extension and directory rules) is read — at most
``AGENT_BOM_IMAGE_SECRET_MAX_FILE_BYTES`` per file and
``AGENT_BOM_IMAGE_SECRET_MAX_FILES`` per image, binaries skipped — and goes
through the same matchers and redaction as ``agent-bom secrets``. OS package
trees (``usr/share``, ``usr/lib``, CA bundles, package databases) are skipped:
they hold vendor test material, not the image owner's secrets.

A secret in a layer stays in that layer's blob even when a higher layer
deletes (whiteout) or overwrites the file, so it is still reported, marked
``in_final_filesystem: false`` with the layer that removed it.
"""

from __future__ import annotations

import tarfile
from pathlib import Path, PurePosixPath

from agent_bom.image_evidence.model import ImageEvidence, active_image_evidence
from agent_bom.parsers.oci_io import _env_int, _safe_getmember
from agent_bom.parsers.oci_layer import _layer_whiteouts, _LayerScan

_DEFAULT_MAX_FILE_BYTES = 1024 * 1024
_DEFAULT_MAX_FILES = 20_000
_BINARY_SNIFF_BYTES = 8192
_SKIP_PREFIXES = (
    "bin/",
    "sbin/",
    "boot/",
    "dev/",
    "proc/",
    "sys/",
    "lib/",
    "lib32/",
    "lib64/",
    "usr/bin/",
    "usr/sbin/",
    "usr/lib/",
    "usr/lib32/",
    "usr/lib64/",
    "usr/libexec/",
    "usr/include/",
    "usr/share/",
    "usr/local/include/",
    "usr/local/share/",
    "var/lib/dpkg/",
    "var/lib/rpm/",
    "var/lib/apk/",
    "var/cache/",
    "var/log/",
    "etc/ssl/",
    "etc/pki/",
    "etc/ca-certificates/",
)


def _candidate(path: str) -> bool:
    from agent_bom.secret_scanner import _should_scan

    if path.startswith(_SKIP_PREFIXES) or PurePosixPath(path).name.startswith(".wh."):
        return False
    return _should_scan(Path(path))


def _read_text(layer_tf: tarfile.TarFile, name: str, evidence: ImageEvidence, max_bytes: int) -> str | None:
    member = _safe_getmember(layer_tf, name)
    if member is None or not member.isfile():
        return None
    if member.size > max_bytes:
        evidence.secret_scan.skipped_large += 1
        return None
    try:
        handle = layer_tf.extractfile(member)
        data = handle.read(max_bytes + 1) if handle is not None else None
    except (tarfile.TarError, OSError):
        return None
    if data is None:
        return None
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        evidence.secret_scan.skipped_binary += 1
        return None
    return data.decode("utf-8", errors="replace")


def _mark_superseded(evidence: ImageEvidence, scan: _LayerScan, present: set[str]) -> None:
    """A higher layer that deletes or rewrites a file removes it from the final filesystem only."""
    layer_index = scan.layer.layer_index
    whiteouts = {w.removeprefix("./") for w in _layer_whiteouts(scan.names)}
    for secret in evidence.layer_secrets:
        if secret["layer_index"] >= layer_index or not secret["in_final_filesystem"]:
            continue
        path = secret["image_path"]
        deleted = path in whiteouts or any(w.endswith("/") and path.startswith(w) for w in whiteouts)
        if deleted or path in present:
            secret["in_final_filesystem"] = False
            secret["removed_in_layer"] = layer_index


def extract_layer_secrets(scan: _LayerScan) -> None:
    """Record hardcoded secrets of one layer into the active image evidence collector."""
    evidence = active_image_evidence()
    if evidence is None:
        return
    from agent_bom.secret_scanner import scan_content

    present = {name.removeprefix("./") for name in scan.names}
    _mark_superseded(evidence, scan, present)
    max_bytes = _env_int("AGENT_BOM_IMAGE_SECRET_MAX_FILE_BYTES", _DEFAULT_MAX_FILE_BYTES)
    max_files = _env_int("AGENT_BOM_IMAGE_SECRET_MAX_FILES", _DEFAULT_MAX_FILES)
    layer_digest = evidence.layer_digest(scan.layer.layer_index) or scan.layer.layer_id
    for name in sorted(scan.names):
        path = name.removeprefix("./")
        if not _candidate(path):
            continue
        if evidence.secret_scan.files_scanned >= max_files:
            evidence.secret_scan.capped = True
            return
        text = _read_text(scan.layer_tf, name, evidence, max_bytes)
        if text is None:
            continue
        evidence.secret_scan.files_scanned += 1
        for finding in scan_content(text, Path(path), f"/{path}"):
            evidence.add_layer_secret(
                {
                    **finding.to_dict(),
                    "location_kind": "layer",
                    "image": evidence.reference,
                    "image_path": path,
                    "layer_index": scan.layer.layer_index,
                    "layer_digest": layer_digest,
                    "in_final_filesystem": True,
                }
            )
