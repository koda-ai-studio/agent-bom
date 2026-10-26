"""Model files inside container image layers: inventory, static pickle scan and findings bound to the image.

SAFETY: payloads are built with ``pickle.dumps`` (serializes only) and are never
deserialized; the scanner under test only disassembles opcodes.
"""

from __future__ import annotations

import io
import json
import pickle
import tarfile
from pathlib import Path

import pytest

from agent_bom import model_pickle_scan
from agent_bom.finding import FindingType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.image import scan_image_tar
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, ServerSurface, TransportType
from agent_bom.output.json_fmt import to_json
from agent_bom.parsers.oci_model_artifacts import (
    MAX_ARTIFACTS_PER_IMAGE,
    attach_image_model_findings,
    collect_model_artifacts,
    model_artifact_metadata,
)


class _Implant:
    def __reduce__(self):
        import os

        return (os.system, ("echo implant",))


def _layer(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as layer:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            layer.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _image(tmp_path: Path, layers: list[dict[str, bytes]]) -> Path:
    paths = [f"{index:040d}/layer.tar" for index in range(len(layers))]
    manifest = json.dumps([{"Config": "config.json", "RepoTags": ["models:test"], "Layers": paths}]).encode()
    image = tmp_path / "image.tar"
    with tarfile.open(image, mode="w:") as outer:
        for path, files in zip(paths, layers, strict=True):
            blob = _layer(files)
            info = tarfile.TarInfo(path)
            info.size = len(blob)
            outer.addfile(info, io.BytesIO(blob))
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        outer.addfile(info, io.BytesIO(manifest))
    return image


def _scan(image: Path) -> tuple[list, dict]:
    with collect_model_artifacts("registry.example/ml/serve:1.0") as collector:
        packages, _strategy = scan_image_tar(str(image))
    return packages, model_artifact_metadata(collector)


def test_malicious_pickle_in_a_layer_is_detected_without_deserializing(tmp_path: Path) -> None:
    image = _image(tmp_path, [{"opt/models/classifier.pkl": pickle.dumps(_Implant()), "opt/models/weights.safetensors": b"{}" * 8}])
    _packages, metadata = _scan(image)
    by_path = {a["image_path"]: a for a in metadata["model_artifacts"]}
    assert set(by_path) == {"opt/models/classifier.pkl", "opt/models/weights.safetensors"}
    flags = {f["type"] for f in by_path["opt/models/classifier.pkl"]["security_flags"]}
    assert "MALICIOUS_PICKLE" in flags
    assert by_path["opt/models/weights.safetensors"]["security_flags"] == []
    assert by_path["opt/models/classifier.pkl"]["layer_id"]  # provenance names the layer


def test_no_collector_means_no_model_work(tmp_path: Path) -> None:
    image = _image(tmp_path, [{"opt/models/classifier.pkl": pickle.dumps(_Implant())}])
    with collect_model_artifacts("other") as collector:
        pass
    scan_image_tar(str(image))
    assert collector.artifacts() == []


def test_whiteout_in_a_higher_layer_removes_the_model(tmp_path: Path) -> None:
    image = _image(
        tmp_path,
        [{"opt/models/classifier.pkl": pickle.dumps(_Implant())}, {"opt/models/.wh.classifier.pkl": b""}],
    )
    _packages, metadata = _scan(image)
    assert metadata == {}


def test_oversize_pickle_member_is_reported_unscanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(model_pickle_scan, "_max_pickle_bytes", lambda: 16)
    import agent_bom.parsers.oci_model_artifacts as artifacts_mod

    monkeypatch.setattr(artifacts_mod, "_max_pickle_bytes", lambda: 16)
    image = _image(tmp_path, [{"opt/models/big.pt": b"PK\x03\x04" + b"\x00" * 64}])
    _packages, metadata = _scan(image)
    (artifact,) = metadata["model_artifacts"]
    assert [f["type"] for f in artifact["security_flags"]] == ["OVERSIZE_PICKLE_UNSCANNED"]


def test_per_image_cap_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.parsers.oci_model_artifacts as artifacts_mod

    monkeypatch.setattr(artifacts_mod, "MAX_ARTIFACTS_PER_IMAGE", 2)
    image = _image(tmp_path, [{f"m/{i}.onnx": b"x" for i in range(4)}])
    _packages, metadata = _scan(image)
    assert len(metadata["model_artifacts"]) == 2 and metadata["model_artifacts_capped"] is True
    assert MAX_ARTIFACTS_PER_IMAGE == 256


def test_findings_are_bound_to_the_image_in_the_stream_and_graph(tmp_path: Path) -> None:
    image = _image(tmp_path, [{"opt/models/classifier.pkl": pickle.dumps(_Implant())}])
    packages, metadata = _scan(image)
    server = MCPServer(name="image.tar", command="", transport=TransportType.STDIO, packages=packages, surface=ServerSurface.OCI_TARBALL)
    agent = Agent(
        name="image-tar:image.tar",
        agent_type=AgentType.CUSTOM,
        config_path="oci-tar://image.tar",
        source="image-tar",
        mcp_servers=[server],
        metadata=metadata,
    )
    report = AIBOMReport(agents=[agent])
    assert attach_image_model_findings(report) == 1
    assert attach_image_model_findings(report) == 0  # idempotent
    findings = [f for f in report.to_findings() if f.evidence.get("image")]
    assert {f.finding_type for f in findings} == {FindingType.MALICIOUS_MODEL}
    (malicious,) = findings
    assert malicious.asset.name == "registry.example/ml/serve:1.0:/opt/models/classifier.pkl"
    assert malicious.asset.identifier == agent.stable_id
    graph = build_unified_graph_from_report(to_json(report))
    (node,) = [n for n in graph.nodes.values() if n.attributes.get("finding_id") == malicious.id or n.id.endswith(malicious.id)]
    holders = [graph.nodes[e.source] for e in graph.reverse_adjacency[node.id] if e.relationship == RelationshipType.VULNERABLE_TO]
    # The image carrier projects as the image node, which keeps the carrier's ids as aliases.
    assert [h.entity_type for h in holders] == [EntityType.CONTAINER]
    assert holders[0].label == "image: image.tar"
    assert agent.stable_id in holders[0].attributes["identity"]["aliases"]
