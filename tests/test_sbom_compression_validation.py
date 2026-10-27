"""Corrupt compressed SBOMs fail with the public validation error contract."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from agent_bom.parsers.sbom_context import load_sbom_agents
from agent_bom.sbom import load_sbom
from agent_bom.sbom_formats.decode import decode_sbom_document

# ClusterFuzzLite #6028: crash-e67381aa9da5cf80317e81fa7df3e6074a9c32e6.
# A valid gzip header followed by a corrupt DEFLATE stored block.
CORRUPT_DEFLATE = b"\x1f\x8b\x08\x00\x60\xff\xff\xff" + b"\x00" * 37 + b"\xff\xff\x0e"


@pytest.mark.parametrize("payload", [CORRUPT_DEFLATE, b"\x1f\x8b", b"\x1f\x8b" + b"\x00" * 20], ids=["deflate", "truncated", "header"])
@pytest.mark.parametrize("intake", ["decode", "packages", "agents"])
def test_corrupt_gzip_sbom_raises_validation_error(tmp_path: Path, payload: bytes, intake: str) -> None:
    path = tmp_path / "bom.json.gz"
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="^SBOM is not a valid gzip stream$"):
        if intake == "decode":
            decode_sbom_document(payload)
        elif intake == "packages":
            load_sbom(str(path))
        else:
            load_sbom_agents(str(path))


def test_valid_gzip_member_followed_by_corrupt_member_is_rejected() -> None:
    payload = gzip.compress(b'{"bomFormat":"CycloneDX","components":[]}') + CORRUPT_DEFLATE
    with pytest.raises(ValueError, match="^SBOM is not a valid gzip stream$"):
        decode_sbom_document(payload)


def test_valid_gzip_sbom_keeps_its_document() -> None:
    payload = gzip.compress(b'{"bomFormat":"CycloneDX","components":[]}', mtime=0)
    assert decode_sbom_document(payload) == {"bomFormat": "CycloneDX", "components": []}
