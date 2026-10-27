"""Daemonless image scans pull straight from the registry, under the same bounds as archive scans."""

from __future__ import annotations

import base64
import json
import os
import shutil

import pytest

from agent_bom.image import ImageScanError, scan_image
from agent_bom.image_evidence import collect_image_evidence
from agent_bom.oci_registry import client as registry_client
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings
from tests._oci_image_builder import build_image, build_index, dpkg_status
from tests._oci_registry_fake import CDN_HOST, REGISTRY, FakeRegistry

REF = f"{REGISTRY}/team/app:1.0"


@pytest.fixture
def registry(monkeypatch):
    fake = FakeRegistry()
    monkeypatch.setattr(registry_client, "_default_transport", fake.transport)
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)  # no Docker daemon, no credential helpers
    monkeypatch.delenv("AGENT_BOM_REGISTRY_USER", raising=False)
    monkeypatch.delenv("AGENT_BOM_REGISTRY_PASS", raising=False)
    reset_scan_warnings()
    return fake


def _image(*packages: tuple[str, str], extra: dict[str, bytes] | None = None):
    return build_image([{"var/lib/dpkg/status": dpkg_status(*packages), "etc/os-release": b"ID=debian\nVERSION_ID=12\n"}, extra or {}])


def test_anonymous_token_flow_scans_without_docker(registry):
    image = _image(("openssl", "3.0.11"), ("bash", "5.2.15"))
    registry.push_image("team/app", image, "1.0")

    with collect_image_evidence(REF) as evidence:
        packages, strategy = scan_image(REF)

    assert strategy == "registry"
    assert sorted(p.name for p in packages) == ["bash", "openssl"]
    assert {p.distro_name for p in packages} == {"debian"}
    assert evidence.source == "registry"
    assert evidence.digest == image.manifest_digest
    assert evidence.layer_digests == image.layer_digests
    assert evidence.platform == "linux/amd64"
    token_requests = [r for r in registry.requests if r.url.path == "/token"]
    assert token_requests and "repository%3Ateam%2Fapp%3Apull" in str(token_requests[0].url)
    assert all(r.method == "GET" for r in registry.requests)


def test_index_selects_default_platform_and_honours_platform_flag(registry):
    amd64, arm64 = _image(("amd64-only", "1")), _image(("arm64-only", "1"))
    registry.push_image("team/app", amd64)
    registry.push_image("team/app", arm64)
    raw, _digest = build_index({"linux/amd64": amd64, "linux/arm64/v8": arm64}, attestation_for="linux/amd64")
    registry.add_manifest("team/app", raw, "application/vnd.oci.image.index.v1+json", "1.0")

    with collect_image_evidence(REF) as default_evidence:
        default_pkgs, _ = scan_image(REF)
    with collect_image_evidence(REF) as arm_evidence:
        arm_pkgs, _ = scan_image(REF, platform="linux/arm64")

    assert [p.name for p in default_pkgs] == ["amd64-only"]
    assert [p.name for p in arm_pkgs] == ["arm64-only"]
    assert arm_evidence.platform == "linux/arm64/v8"
    assert default_evidence.available_platforms == ["linux/amd64", "linux/arm64/v8"]
    assert default_evidence.index_digest == _digest
    with pytest.raises(ImageScanError, match=r"no linux/s390x manifest \(available: linux/amd64, linux/arm64/v8\)"):
        scan_image(REF, platform="linux/s390x", pull_mode="registry")


def test_docker_config_credentials_drive_the_token_request(registry, tmp_path, monkeypatch):
    registry.auth = "token-basic"
    registry.push_image("team/app", _image(("curl", "8.5.0")), "1.0")
    encoded = base64.b64encode(f"{registry.username}:{registry.password}".encode()).decode()
    (tmp_path / "config.json").write_text(json.dumps({"auths": {REGISTRY: {"auth": encoded}}}))
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))

    with collect_image_evidence(REF) as evidence:
        packages, strategy = scan_image(REF)

    assert (strategy, [p.name for p in packages]) == ("registry", ["curl"])
    assert evidence.credential_source == "docker-config"
    assert registry.password not in json.dumps(evidence.to_metadata())


def test_basic_auth_registry_uses_explicit_credentials(registry):
    registry.auth = "basic"
    registry.push_image("team/app", _image(("zlib", "1.3")), "1.0")

    packages, strategy = scan_image(REF, registry_user=registry.username, registry_pass=registry.password, pull_mode="registry")

    assert (strategy, [p.name for p in packages]) == ("registry", ["zlib"])


def test_blob_redirect_to_cdn_never_forwards_registry_credentials(registry):
    registry.redirect_blobs = True
    registry.push_image("team/app", _image(("tar", "1.35")), "1.0")

    packages, _ = scan_image(REF)

    assert [p.name for p in packages] == ["tar"]
    cdn = [r for r in registry.requests if r.url.host == CDN_HOST]
    assert cdn and all("authorization" not in r.headers for r in cdn)


def test_corrupt_layer_is_a_coverage_gap_not_a_clean_layer(registry):
    image = build_image(
        [{"var/lib/dpkg/status": dpkg_status(("bash", "5.2"))}, {"var/lib/dpkg/status": dpkg_status(("bash", "5.2"), ("nginx", "1.25"))}]
    )
    registry.push_image("team/app", image, "1.0")
    registry.corrupt_blob = image.layer_digests[1]

    packages, _ = scan_image(REF)

    assert [p.name for p in packages] == ["bash"]
    reasons = {w["reason"] for w in consume_coverage_warnings()}
    assert "oci_layer_download_failed" in reasons


def test_layer_over_the_compressed_limit_is_skipped_before_download(registry, monkeypatch):
    image = _image(("bash", "5.2"), extra={"opt/blob.bin": os.urandom(16384)})
    registry.push_image("team/app", image, "1.0")
    base_size, big_size = (len(image.blobs[d]) for d in image.layer_digests)
    assert big_size > base_size + 1
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_LAYER_COMPRESSED_BYTES", str(base_size + 1))

    packages, _ = scan_image(REF)

    assert [p.name for p in packages] == ["bash"]

    assert "oci_layer_size_limit" in {w["reason"] for w in consume_coverage_warnings()}
    downloaded = {r.url.path.rsplit("/", 1)[-1] for r in registry.requests if "/blobs/" in r.url.path}
    assert len(downloaded & set(image.layer_digests)) == 1


def test_registry_failure_falls_back_to_daemon_with_a_clear_note(registry, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    monkeypatch.setattr("agent_bom.image._scan_with_docker", lambda ref, platform=None: build_image([]) and [_pkg()])
    monkeypatch.setattr("agent_bom.image._daemon_supply_chain", lambda *a: None)

    with collect_image_evidence("team/local-only:dev") as evidence:
        packages, strategy = scan_image("team/local-only:dev")

    assert strategy == "native" and packages
    assert evidence.source == "daemon"
    assert any("Registry pull failed" in note for note in evidence.notes)


def test_no_registry_and_no_docker_reports_both_failures(registry):
    with pytest.raises(ImageScanError) as excinfo:
        scan_image(f"{REGISTRY}/team/missing:1")
    assert "Registry pull failed" in str(excinfo.value) and "Docker is not available" in str(excinfo.value)


def test_daemon_mode_and_offline_mode_never_contact_the_registry(registry, monkeypatch):
    from agent_bom import http_client

    with pytest.raises(ImageScanError, match="Docker is not available"):
        scan_image(REF, pull_mode="daemon")
    monkeypatch.setattr(http_client, "_OFFLINE", True)
    with pytest.raises(ImageScanError, match="Docker is not available"):
        scan_image(REF)
    with pytest.raises(ImageScanError, match="needs network access"):
        scan_image(REF, pull_mode="registry")
    assert registry.requests == []


def test_zstd_layers_are_named_gaps(registry):
    image = _image(("bash", "5.2"))
    image.manifest["layers"].append(
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": "sha256:" + "d" * 64, "size": 10}
    )
    raw = json.dumps(image.manifest).encode()
    registry.blobs.update(image.blobs)
    registry.add_manifest("team/app", raw, image.manifest["mediaType"], "1.0")

    packages, _ = scan_image(REF)

    assert [p.name for p in packages] == ["bash"]
    assert "oci_layer_unsupported_media_type" in {w["reason"] for w in consume_coverage_warnings()}


def _pkg():
    from agent_bom.models import Package

    return Package(name="local", version="1", ecosystem="deb")


@pytest.mark.parametrize(
    "field,value",
    [("layers", 7), ("layers", [None]), ("config", []), ("layers", [{"digest": "sha256:" + "a" * 64, "size": "not-a-number"}])],
)
def test_malformed_manifest_fails_with_typed_scan_error(registry, field, value):
    image = _image(("bash", "5.2"))
    registry.push_image("team/app", image, "1.0")
    import json

    document = dict(image.manifest)
    document[field] = value
    registry.add_manifest("team/app", json.dumps(document).encode(), "application/vnd.oci.image.manifest.v1+json", "1.0")
    with pytest.raises(ImageScanError, match="invalid"):
        scan_image(REF, pull_mode="registry")


@pytest.mark.parametrize("history", [["bad"], 7, [{"created_by": []}], [{"empty_layer": "false"}]])
def test_malformed_config_history_fails_with_typed_scan_error(registry, history):
    import json

    image = _image(("bash", "5.2"))
    registry.push_image("team/app", image, "1.0")
    config = {**image.config, "history": history}
    raw_config = json.dumps(config).encode()
    digest = registry.add_blob(raw_config)
    manifest = {**image.manifest, "config": {**image.manifest["config"], "digest": digest, "size": len(raw_config)}}
    registry.add_manifest("team/app", json.dumps(manifest).encode(), "application/vnd.oci.image.manifest.v1+json", "1.0")
    with pytest.raises(ImageScanError, match="invalid metadata"):
        scan_image(REF, pull_mode="registry")
