"""Container application locations and distroless package receipts are inventory."""

import pytest

from agent_bom.oci_parser import parse_oci_tarball
from tests.test_oci_candidate_coverage import _docker_save_tar


@pytest.mark.parametrize("path", ["server/github-mcp-server", "app/server", "ko-app/cosign", "bin/server", "opt/service/server"])
def test_go_application_locations(tmp_path, path):
    blob = b"\xff Go buildinf:\x00\x00\x00\x00\ndep\tgithub.com/spf13/cobra\tv1.8.0\th1:abc=\n" + b"\x00" * 256
    result = parse_oci_tarball(_docker_save_tar(tmp_path, path, blob))
    assert [(p.name, p.version) for p in result.packages] == [("github.com/spf13/cobra", "v1.8.0")]


def test_distroless_dpkg_status_fragment(tmp_path):
    result = parse_oci_tarball(
        _docker_save_tar(tmp_path, "var/lib/dpkg/status.d/libc6", b"Package: libc6\nVersion: 2.36-9\nArchitecture: arm64\n")
    )
    assert [(p.name, p.version) for p in result.packages] == [("libc6", "2.36-9")]


@pytest.mark.parametrize("offset", [-4, 64])
def test_go_buildinfo_beyond_first_read_window(tmp_path, offset):
    from agent_bom.parsers.oci_types import _GO_BIN_MAX_READ

    blob = b"\x7fELF" + b"\x00" * (_GO_BIN_MAX_READ + offset - 4)
    blob += b"\xff Go buildinf:\x00\x00\x00\x00\ndep\tgithub.com/spf13/cobra\tv1.8.0\th1:abc=\n"
    result = parse_oci_tarball(_docker_save_tar(tmp_path, "server/github-mcp-server", blob))
    assert [(p.name, p.version) for p in result.packages] == [("github.com/spf13/cobra", "v1.8.0")]


def test_oversized_go_candidate_reports_inventory_gap(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_METADATA_MEMBER_BYTES", "128")
    blob = b"\xff Go buildinf:\ndep\tgithub.com/spf13/cobra\tv1.8.0\n" + b"\x00" * 256
    result = parse_oci_tarball(_docker_save_tar(tmp_path, "server/github-mcp-server", blob))
    assert result.packages == []
    assert any(w.path == "server/github-mcp-server" for w in result.coverage_warnings)


@pytest.mark.parametrize("filename, expected_gap", [("libc6.md5sums", False), ("libc6", True)])
def test_distroless_checksums_are_not_status_records(tmp_path, filename, expected_gap):
    blob = b"d41d8cd98f00b204e9800998ecf8427e  usr/share/doc/libc6/copyright\n"
    result = parse_oci_tarball(_docker_save_tar(tmp_path, f"var/lib/dpkg/status.d/{filename}", blob))
    assert result.packages == []
    assert bool(result.coverage_warnings) is expected_gap


@pytest.mark.parametrize("path", ["opt/model/weights.bin", "app/README.md", "srv/static/data.json"])
def test_oversized_non_binary_is_not_a_go_coverage_gap(tmp_path, monkeypatch, path):
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_METADATA_MEMBER_BYTES", "128")
    result = parse_oci_tarball(_docker_save_tar(tmp_path, path, b"documentation and data\n" * 20))
    assert result.packages == []
    assert not result.coverage_warnings


def test_non_binary_probe_stops_before_searching_body(tmp_path, monkeypatch):
    from agent_bom.parsers import oci_extractors

    def unexpected_search(stream):
        pytest.fail("Non-executable content must not enter the Go marker search")

    monkeypatch.setattr(oci_extractors, "_go_buildinfo_window", unexpected_search)
    result = parse_oci_tarball(_docker_save_tar(tmp_path, "app/data.bin", b"data" * 1024))
    assert not result.coverage_warnings


@pytest.mark.parametrize("header", [b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe"])
def test_oversized_executable_still_records_unknown_inventory(tmp_path, monkeypatch, header):
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_METADATA_MEMBER_BYTES", "128")
    result = parse_oci_tarball(_docker_save_tar(tmp_path, "app/server", header + bytes(512)))
    assert any(w.path == "app/server" for w in result.coverage_warnings)
