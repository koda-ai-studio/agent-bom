"""Machine-image side-scan support is stated per provider, never implied."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cloud.side_scan_lifecycle import side_scan_provider_capabilities


def test_image_scan_capability_is_honest_per_provider() -> None:
    caps = {provider: cap.to_dict() for provider, cap in side_scan_provider_capabilities().items()}

    assert caps["aws"]["image_scan"] == "ami"
    assert caps["gcp"]["image_scan"] == "image"
    assert caps["azure"]["image_scan"] == "unsupported"
    assert "managed image" in str(caps["azure"]["image_scan_note"])
    for cap in caps.values():
        # The side-scan creates and deletes temp disks: never advertised as read-only.
        assert cap["mutation"] == "opt_in_temp_disk_lifecycle"


def test_capabilities_cli_shows_image_support() -> None:
    from agent_bom.cli._cloud_group import side_scan_capabilities_cmd

    table = CliRunner().invoke(side_scan_capabilities_cmd, [], env={"COLUMNS": "200"})
    assert table.exit_code == 0, table.output
    assert "Images" in table.output
    assert "unsupported" in table.output

    raw = CliRunner().invoke(side_scan_capabilities_cmd, ["-f", "json"])
    rows = {row["provider"]: row for row in json.loads(raw.output)}
    assert rows["azure"]["image_scan"] == "unsupported"
