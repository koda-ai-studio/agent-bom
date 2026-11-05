"""Untrusted image labels cannot exhaust redaction's CPU budget."""

import subprocess
import sys

import pytest

from agent_bom.security import sanitize_sensitive_payload


def test_oversized_coordinate_does_not_bypass_full_value_inspection(monkeypatch):
    from agent_bom import security

    value = "a" * 4097 + "@sha256:" + "0" * 64
    inspected = []
    monkeypatch.setattr(security, "_is_obfuscated_credential", lambda text: inspected.append(text) or False)
    security._looks_sensitive_value(value)
    assert inspected == [value]


@pytest.mark.parametrize("unit", ["0", "0-", "-0"])
def test_adversarial_image_label_finishes_within_process_budget(unit):
    # A subprocess makes the regression safe even if a regex stalls the GIL.
    script = (
        "from agent_bom.security import _looks_sensitive_value; "
        f'result = _looks_sensitive_value("0" + {unit!r} * 100000); '
        "assert isinstance(result, bool)"
    )
    subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, timeout=5)


@pytest.mark.parametrize("name", ["python", "python:3.11", "localhost:5000/team/image:V1_2", "ghcr.io/team/image"])
def test_digest_coordinates_preserve_registry_port_and_tag(name):
    value = name + "@sha256:" + "603975e62d85aa07578034d3d10ffa1983b7618a6abb6371cf51941be6b8842c"
    assert sanitize_sensitive_payload({"image": value}) == {"image": value}


@pytest.mark.parametrize(
    "reference",
    [
        "",
        "/image",
        "image/",
        "team//image",
        "team/../image",
        "im--age",
        "host:123456/image",
        "host:abc/image",
        "image:",
        "image:" + "v" * 129,
    ],
)
def test_malformed_coordinates_do_not_receive_digest_exception(reference):
    from agent_bom.redaction.image_coordinates import is_digest_image_coordinate

    assert not is_digest_image_coordinate(reference + "@sha256:" + "0" * 64)


@pytest.mark.parametrize("digest", ["0" * 63, "0" * 65, "G" * 64, "0" * 63 + "\n"])
def test_invalid_digest_does_not_receive_exception(digest):
    from agent_bom.redaction.image_coordinates import is_digest_image_coordinate

    assert not is_digest_image_coordinate("image@sha256:" + digest)
