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
