"""Secrets baked into image layers, ENV and build history are found, bound to the layer, and redacted."""

from __future__ import annotations

import json

import pytest

from agent_bom.image_evidence import collect_image_evidence
from agent_bom.oci_parser import parse_oci_layout_dir
from tests._oci_image_builder import build_image, dpkg_status

# Built from fragments so no provider-shaped key literal sits in the source.
_AWS_KEY_ID = "AK" + "IA" + "Q3EGRT7ZXMPLW2NB"
_GH_TOKEN = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def _scan(tmp_path, image):
    with collect_image_evidence("registry.example.test/team/app:1") as evidence:
        result = parse_oci_layout_dir(image.write_layout(tmp_path / "layout"))
    return result, evidence


def test_secret_in_app_layer_is_found_with_layer_digest_and_redacted(tmp_path):
    image = build_image(
        [
            {"var/lib/dpkg/status": dpkg_status(("bash", "5.2"))},
            {"app/config/settings.py": f'AWS_ACCESS_KEY_ID = "{_AWS_KEY_ID}"\n'.encode()},
        ]
    )
    result, evidence = _scan(tmp_path, image)

    assert [p.name for p in result.packages] == ["bash"]
    [secret] = evidence.layer_secrets
    assert secret["type"] == "AWS Access Key"
    assert secret["image_path"] == "app/config/settings.py"
    assert secret["layer_index"] == 2
    assert secret["layer_digest"] == image.layer_digests[1]
    assert secret["in_final_filesystem"] is True
    assert secret["preview"] == "[CREDENTIAL_REDACTED]"
    assert _AWS_KEY_ID not in json.dumps(evidence.to_metadata())
    assert evidence.secret_scan.files_scanned == 1


def test_whiteout_keeps_secret_reported_but_marks_it_removed(tmp_path):
    image = build_image(
        [
            {"root/.config/token.txt": f"token={_GH_TOKEN}\n".encode()},
            {"root/.config/.wh.token.txt": b""},
        ]
    )
    _result, evidence = _scan(tmp_path, image)

    [secret] = evidence.layer_secrets
    assert secret["layer_index"] == 1
    assert secret["in_final_filesystem"] is False
    assert secret["removed_in_layer"] == 2


def test_os_package_trees_binaries_and_large_files_are_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_IMAGE_SECRET_MAX_FILE_BYTES", "64")
    image = build_image(
        [
            {
                "usr/share/doc/pkg/example.txt": f"key {_AWS_KEY_ID}\n".encode(),
                "app/blob.json": b"\x00\x01" + _AWS_KEY_ID.encode(),
                "app/big.txt": (f"key {_AWS_KEY_ID}\n" * 20).encode(),
            }
        ]
    )
    _result, evidence = _scan(tmp_path, image)

    assert evidence.layer_secrets == []
    assert evidence.secret_scan.skipped_binary == 1
    assert evidence.secret_scan.skipped_large == 1


def test_env_and_build_arg_secrets_are_flagged_without_values(tmp_path):
    image = build_image(
        [{"etc/hostname": b"app\n"}],
        env=["PATH=/usr/bin", "DB_PASSWORD=s3cr3t-Prod-Value", "LOG_LEVEL=info", "API_TOKEN_FILE=/run/secrets/token"],
        history=[f"|1 GITHUB_TOKEN={_GH_TOKEN} /bin/sh -c make build"],
    )
    result, evidence = _scan(tmp_path, image)

    kinds = sorted((s["location_kind"], s["file"]) for s in evidence.config_secrets)
    assert kinds == [("config_env", "image config ENV DB_PASSWORD"), ("history", "image history step 1")]
    payload = json.dumps(evidence.to_metadata())
    assert "s3cr3t-Prod-Value" not in payload and _GH_TOKEN not in payload
    occurrence_dump = json.dumps([o.to_dict() for p in result.packages for o in p.occurrences])
    assert _GH_TOKEN not in occurrence_dump


def test_history_created_by_is_redacted_in_layer_provenance(tmp_path):
    image = build_image(
        [{"var/lib/dpkg/status": dpkg_status(("curl", "8.5.0"))}],
        history=[f"|1 GITHUB_TOKEN={_GH_TOKEN} /bin/sh -c apt-get install -y curl"],
    )
    result, _evidence = _scan(tmp_path, image)

    [occurrence] = result.packages[0].occurrences
    assert _GH_TOKEN not in (occurrence.created_by or "")
    assert "apt-get install" in (occurrence.created_by or "")


def test_no_collector_means_no_secret_work(tmp_path):
    image = build_image([{"app/settings.py": f'KEY = "{_AWS_KEY_ID}"\n'.encode()}])
    result = parse_oci_layout_dir(image.write_layout(tmp_path / "layout"))
    assert result.packages == []


@pytest.mark.parametrize("length", [40, 64])
def test_gpg_public_fingerprint_is_not_a_credential(tmp_path, length):
    fingerprint = ("0123456789ABCDEF" * 4)[:length]
    image = build_image(
        [{"etc/hostname": b"app\n"}],
        env=[f"GPG_KEY={fingerprint}"],
        history=[f"/bin/sh -c #(nop) ENV GPG_KEY={fingerprint}"],
    )
    _, evidence = _scan(tmp_path, image)
    assert evidence.config_secrets == []


@pytest.mark.parametrize("key", ["GPG_KEY", "API_KEY"])
def test_gpg_exception_does_not_hide_secret_material(tmp_path, key):
    value = "fixture-" + "private-key-material" if key == "GPG_KEY" else "".join(format(n, "X") for n in range(16)) * 4
    image = build_image([{"etc/hostname": b"app\n"}], env=[f"{key}={value}"])
    _, evidence = _scan(tmp_path, image)
    assert len(evidence.config_secrets) == 1
    assert value not in json.dumps(evidence.to_metadata())


def test_stdlib_module_catalog_does_not_mask_adjacent_layer_credentials(tmp_path):
    value = "fixture-" + "credential-381"
    source = "module_docs = {'pwd': 'pwd#module-pwd', 'spwd': 'spwd#module-spwd'}\n"
    image = build_image(
        [
            {
                "usr/local/lib/python3.14/pydoc_data/module_docs.py": source.encode(),
                "app/config.py": f'password = "{value}"\n'.encode(),
            }
        ]
    )
    _, evidence = _scan(tmp_path, image)
    assert [s["image_path"] for s in evidence.layer_secrets] == ["app/config.py"]
    assert value not in json.dumps(evidence.to_metadata())
