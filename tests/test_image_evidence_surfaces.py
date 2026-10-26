"""Image evidence reaches every surface: CLI console + JSON, unified findings, the graph image node, the policy gate."""

from __future__ import annotations

import base64
import json
import shutil
from typing import Any

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agent_bom.cli import main
from agent_bom.oci_registry import client as registry_client
from tests._oci_image_builder import OCI_MANIFEST, build_image, dpkg_status
from tests._oci_registry_fake import REGISTRY, FakeRegistry

REF = f"{REGISTRY}/team/app:1.0"
_AWS_KEY_ID = "AK" + "IA" + "Q3EGRT7ZXMPLW2NB"


@pytest.fixture
def registry(monkeypatch, tmp_path):
    fake = FakeRegistry()
    monkeypatch.setattr(registry_client, "_default_transport", fake.transport)
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    monkeypatch.chdir(tmp_path)
    image = build_image(
        [
            {"var/lib/dpkg/status": dpkg_status(("bash", "5.2.15"))},
            {"srv/app/settings.yaml": f"aws_access_key_id: {_AWS_KEY_ID}\n".encode()},
        ],
        env=["PATH=/usr/bin", "DB_PASSWORD=prod-db-pass-123"],
    )
    fake.push_image("team/app", image, "1.0")
    fake.image = image  # type: ignore[attr-defined]
    return fake


def _sign(registry: FakeRegistry, tmp_path) -> str:
    digest = registry.image.manifest_digest
    payload = json.dumps({"critical": {"image": {"docker-manifest-digest": digest}, "type": "cosign container image signature"}}).encode()
    private = ec.generate_private_key(ec.SECP256R1())
    signature = base64.b64encode(private.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()
    layer = {
        "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
        "digest": registry.add_blob(payload),
        "size": len(payload),
        "annotations": {"dev.cosignproject.cosign/signature": signature},
    }
    manifest = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": {"digest": registry.add_blob(b"{}"), "size": 2}, "layers": [layer]}
    registry.add_manifest("team/app", json.dumps(manifest).encode(), OCI_MANIFEST, digest.replace(":", "-") + ".sig")
    key_path = tmp_path / "cosign.pub"
    key_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return str(key_path)


def _scan(tmp_path, *extra: str) -> tuple[Any, dict[str, Any]]:
    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "--image", REF, "--no-scan", "-f", "json", "-o", str(out), *extra])
    return result, json.loads(out.read_text())


def _image_agent(report: dict[str, Any]) -> dict[str, Any]:
    return next(agent for agent in report["agents"] if agent["name"] == f"image:{REF}")


def test_json_report_carries_signature_digest_and_redacted_secret_findings(registry, tmp_path):
    key = _sign(registry, tmp_path)
    result, report = _scan(tmp_path, "--image-cosign-key", key)

    # Hardcoded secrets in an image are CREDENTIAL_EXPOSURE findings: they trip the default high gate.
    assert result.exit_code == 1
    assert "CREDENTIAL_EXPOSURE" in result.output
    image = _image_agent(report)["metadata"]["image"]
    assert image["source"] == "registry"
    assert image["digest"] == registry.image.manifest_digest
    assert image["signature"]["status"] == "verified"
    secrets = [f for f in report["findings"] if f["source"] == "SECRET_SCAN" and f["evidence"].get("image")]
    kinds = sorted(f["evidence"]["location_kind"] for f in secrets)
    assert kinds == ["config_env", "layer"]
    layer_finding = next(f for f in secrets if f["evidence"]["location_kind"] == "layer")
    assert layer_finding["evidence"]["layer_digest"] == registry.image.layer_digests[1]
    assert layer_finding["evidence"]["image"] == REF and layer_finding["asset"]["asset_type"] == "server"
    raw = json.dumps(report)
    assert _AWS_KEY_ID not in raw and "prod-db-pass-123" not in raw
    assert "signature: verified" in result.output
    assert "secrets: 2 hardcoded secret(s)" in result.output


def test_graph_image_node_carries_evidence_and_secret_findings_attach_to_it(registry, tmp_path):
    from agent_bom.graph.builder import build_unified_graph_from_report

    _result, report = _scan(tmp_path)
    graph = build_unified_graph_from_report(report)

    [image_node] = [n for n in graph.nodes.values() if n.attributes.get("image")]
    assert image_node.attributes["image"]["digest"] == registry.image.manifest_digest
    assert image_node.attributes["image"]["signature_status"] == "unsigned"
    assert image_node.attributes["image"]["secret_count"] == 2
    secret_ids = {f"misconfig:secret_scan:{f['id']}" for f in report["findings"] if f["evidence"].get("image")}
    attached = {edge.target for edge in graph.edges_from(image_node.id)} | {edge.source for edge in graph.edges_to(image_node.id)}
    assert secret_ids and secret_ids <= attached
    invented = [n.id for n in graph.nodes.values() if n.id.startswith(("config_file:", "application:", "source_file:"))]
    assert invented == [], "an image path must never become a repository file or application"


def test_require_image_signature_fails_unsigned_and_passes_verified(registry, tmp_path):
    clean = build_image([{"var/lib/dpkg/status": dpkg_status(("bash", "5.2.15"))}])
    registry.push_image("team/app", clean, "1.0")
    registry.image = clean
    result, _report = _scan(tmp_path, "--require-image-signature")
    assert result.exit_code == 1
    assert "Image policy" in result.output and "unsigned" in result.output

    key = _sign(registry, tmp_path)
    result, _report = _scan(tmp_path, "--require-image-signature", "--image-cosign-key", key)
    assert result.exit_code == 0, result.output


def test_focused_image_command_forwards_pull_mode_and_key(monkeypatch, tmp_path):
    seen: dict[str, Any] = {}

    def fake_scan_image(image_ref, **kwargs):
        from agent_bom.image_evidence.model import active_image_evidence

        seen.update(kwargs, cosign_key=active_image_evidence().cosign_key_path)
        from agent_bom.models import Package

        return [Package(name="bash", version="5.2", ecosystem="deb")], "registry"

    monkeypatch.setattr("agent_bom.image.scan_image", fake_scan_image)
    key = tmp_path / "k.pub"
    key.write_text("x")
    CliRunner().invoke(main, ["image", "ghcr.io/org/app:1", "--pull-mode", "registry", "--cosign-key", str(key), "--offline", "-q"])

    assert seen["pull_mode"] == "registry"
    assert seen["cosign_key"] == str(key)
