"""Model artifacts inside container image layers: inventory plus static pickle scan.

The layer stage runs only while a caller holds :func:`collect_model_artifacts`
for the image, so plain package scans pay nothing. For each layer member with a
model extension (the same table as the filesystem model scan) it records the
file, and for pickle-bearing formats it copies the member into a private
temporary file and disassembles the opcodes with
:mod:`agent_bom.model_pickle_scan` — the model is never deserialized.

Bounds match the filesystem scan: a pickle-bearing member larger than the
pickle byte cap (``AGENT_BOM_PICKLE_MAX_BYTES``) is not copied and is reported
as ``OVERSIZE_PICKLE_UNSCANNED``; at most ``MAX_ARTIFACTS_PER_IMAGE`` files are
recorded per image and the collector says when it stopped. Layer size,
member count and decompression limits are the OCI parser's own: this stage
reads only members of a layer the parser already opened within those limits.
Artifacts deleted by a whiteout in a higher layer are dropped, and a path
rewritten in a higher layer keeps only its newest copy.
"""

from __future__ import annotations

import shutil
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import IO, Any

from agent_bom.domain.finding_model import Finding
from agent_bom.model_files import _MODEL_EXTENSIONS, _SECURITY_FLAGS, _human_size, model_file_findings
from agent_bom.model_pickle_scan import PICKLE_BEARING_EXTENSIONS, PickleScanResult, _max_pickle_bytes, scan_pickle_file_flags
from agent_bom.parsers.model_file_types import MAX_STARTUP_BYTES, is_python_startup_text
from agent_bom.parsers.oci_io import _safe_getmember
from agent_bom.parsers.oci_layer import _layer_whiteouts

MAX_ARTIFACTS_PER_IMAGE = 256
_ACTIVE: ContextVar[ModelArtifactCollector | None] = ContextVar("oci_model_artifacts", default=None)


@dataclass
class ModelArtifactCollector:
    image: str
    by_path: dict[str, dict[str, Any]] = field(default_factory=dict)
    whiteouts_by_layer: dict[int, set[str]] = field(default_factory=dict)
    capped: bool = False

    def record(self, artifact: dict[str, Any]) -> None:
        path = artifact["image_path"]
        if path not in self.by_path and len(self.by_path) >= MAX_ARTIFACTS_PER_IMAGE:
            self.capped = True
            return
        previous = self.by_path.get(path)
        if previous is None or previous["layer_index"] <= artifact["layer_index"]:
            self.by_path[path] = artifact

    def _deleted_later(self, artifact: dict[str, Any]) -> bool:
        path = artifact["image_path"]
        for index, whiteouts in self.whiteouts_by_layer.items():
            if index <= artifact["layer_index"]:
                continue
            if path in whiteouts or any(w.endswith("/") and path.startswith(w) for w in whiteouts):
                return True
        return False

    def artifacts(self) -> list[dict[str, Any]]:
        """Final image view, ``scan_model_files``-shaped plus image and layer provenance."""
        return [a for _, a in sorted(self.by_path.items()) if not self._deleted_later(a)]


@contextmanager
def collect_model_artifacts(image: str) -> Iterator[ModelArtifactCollector]:
    collector = ModelArtifactCollector(image=image)
    token = _ACTIVE.set(collector)
    try:
        yield collector
    finally:
        _ACTIVE.reset(token)


def _open_member(layer_tf: tarfile.TarFile, member: tarfile.TarInfo) -> IO[bytes] | None:
    try:
        return layer_tf.extractfile(member)
    except (tarfile.TarError, OSError):
        return None


def _pickle_flags(layer_tf: tarfile.TarFile, member: tarfile.TarInfo) -> list[dict[str, Any]]:
    cap = _max_pickle_bytes()
    if member.size > cap:
        oversize = PickleScanResult(path=member.name, oversize_unscanned=True, declared_size=member.size, verdict="incomplete")
        return [flag] if (flag := oversize.to_security_flag()) else []
    stream = _open_member(layer_tf, member)
    if stream is None:
        error = PickleScanResult(path=member.name, error="layer member could not be read", verdict="error")
        return [flag] if (flag := error.to_security_flag()) else []
    with tempfile.NamedTemporaryFile(prefix="agent-bom-model-", suffix=PurePosixPath(member.name).suffix) as handle:
        shutil.copyfileobj(stream, handle, length=1024 * 1024)
        handle.flush()
        flags, _ = scan_pickle_file_flags(handle.name)
    return flags


def extract_model_artifacts_layer(scan: Any) -> None:
    """Record model files of one layer (``oci_parser._LayerScan``) into the active collector."""
    collector = _ACTIVE.get()
    if collector is None:
        return
    whiteouts = {path.removeprefix("./") for path in _layer_whiteouts(scan.names)}
    collector.whiteouts_by_layer.setdefault(scan.layer.layer_index, set()).update(whiteouts)
    for name in sorted(scan.names):
        ext = PurePosixPath(name).suffix.lower()
        info = _MODEL_EXTENSIONS.get(ext)
        if info is None or scan.is_deleted(name) or PurePosixPath(name).name.startswith(".wh."):
            continue
        member = _safe_getmember(scan.layer_tf, name)
        if member is None or not member.isfile():
            continue
        if ext == ".pth" and member.size <= MAX_STARTUP_BYTES:
            stream = _open_member(scan.layer_tf, member)
            if stream is not None and is_python_startup_text(stream.read(MAX_STARTUP_BYTES + 1)):
                continue
        flags: list[dict[str, Any]] = [dict(_SECURITY_FLAGS[ext])] if ext in _SECURITY_FLAGS else []
        if ext in PICKLE_BEARING_EXTENSIONS:
            flags.extend(_pickle_flags(scan.layer_tf, member))
        if info.get("min_size_mb") and member.size < info["min_size_mb"] * 1024 * 1024 and not flags:
            continue
        rel = name.removeprefix("./")
        collector.record(
            {
                "path": f"{collector.image}:/{rel}",
                "image_path": rel,
                "image": collector.image,
                "filename": PurePosixPath(rel).name,
                "extension": ext,
                "format": info["format"],
                "ecosystem": info["ecosystem"],
                "size_bytes": member.size,
                "size_human": _human_size(member.size),
                "security_flags": flags,
                "layer_index": scan.layer.layer_index,
                "layer_id": scan.layer.layer_id,
            }
        )


def model_artifact_metadata(collector: ModelArtifactCollector) -> dict[str, Any]:
    """Agent metadata for an image scan: the final artifacts, and whether the per-image cap was hit."""
    artifacts = collector.artifacts()
    if not artifacts:
        return {}
    return {"model_artifacts": artifacts, **({"model_artifacts_capped": True} if collector.capped else {})}


def model_artifact_findings(image: str, agent_stable_id: str, artifacts: list[dict[str, Any]]) -> list[Finding]:
    """Unified model-scan findings for one image, bound to the image's agent node."""
    by_path = {a["path"]: a for a in artifacts}
    findings = model_file_findings(artifacts)
    for finding in findings:
        artifact = by_path.get(finding.asset.identifier or "", {})
        finding.asset.name = f"{image}:/{artifact.get('image_path') or finding.asset.name}"
        finding.asset.asset_type = "agent"
        finding.asset.identifier = agent_stable_id or finding.asset.identifier
        finding.asset.location = image
        finding.evidence.update(image=image, image_path=artifact.get("image_path"), layer_index=artifact.get("layer_index"))
    return findings


def attach_image_model_findings(report: Any) -> int:
    """Append model findings for every image agent that recorded layer artifacts; returns how many were added."""
    existing = {finding.id for finding in report.findings}
    added = 0
    for agent in report.agents:
        artifacts = agent.metadata.get("model_artifacts") if isinstance(agent.metadata, dict) else None
        if not isinstance(artifacts, list) or not artifacts:
            continue
        image = str(artifacts[0].get("image") or agent.name)
        for finding in model_artifact_findings(image, agent.stable_id, artifacts):
            if finding.id not in existing:
                report.findings.append(finding)
                existing.add(finding.id)
                added += 1
    return added
