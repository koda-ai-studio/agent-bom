"""go.sum verification reads the real sumdb lookup record format (network mocked)."""

from __future__ import annotations

from unittest.mock import patch

from agent_bom.parsers.go_resolution import verify_go_checksums

MOD = "github.com/Masterminds/semver/v3"
GO_SUM = (
    f"{MOD} v3.2.1 h1:RN9w6+7QoMeJVGyfmbcgs28Br8cvmnucEXnY0rYXWg0=\n{MOD} v3.2.1/go.mod h1:qvl/7zhW3nngYb5+80sSMF+FG2BjYrf8m9wsX0PNOMQ=\n"
)


def _record(zip_hash: str) -> bytes:
    return (
        "17234567\n"
        f"{MOD} v3.2.1/go.mod h1:qvl/7zhW3nngYb5+80sSMF+FG2BjYrf8m9wsX0PNOMQ=\n"
        f"{MOD} v3.2.1 {zip_hash}\n"
        "\n"
        "go.sum database tree\n18000000\nabc=\n\n— sum.golang.org Az3grlmoo...\n"
    ).encode()


def test_lookup_record_lines_verify_ok_and_use_case_encoded_path(tmp_path):
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(GO_SUM)
    with patch("agent_bom.http_client.fetch_bytes", return_value=_record("h1:RN9w6+7QoMeJVGyfmbcgs28Br8cvmnucEXnY0rYXWg0=")) as fetch:
        result = verify_go_checksums(go_sum, [(MOD, "v3.2.1")])

    assert result == {f"{MOD}@v3.2.1": "ok"}
    assert fetch.call_args.args[0] == "https://sum.golang.org/lookup/github.com/!masterminds/semver/v3@v3.2.1"


def test_lookup_record_detects_mismatch(tmp_path):
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(GO_SUM)
    with patch("agent_bom.http_client.fetch_bytes", return_value=_record("h1:TAMPERED=")):
        result = verify_go_checksums(go_sum, [(MOD, "v3.2.1")])
    assert result == {f"{MOD}@v3.2.1": "mismatch"}
