"""The UI's Kubernetes graph fixture must be what the projection emits today."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_committed_fixture_matches_the_projection():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_k8s_graph_fixture.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_fixture_receipts_use_a_recorded_time_instead_of_the_build_clock():
    import runpy

    module = runpy.run_path(str(ROOT / "scripts" / "generate_k8s_graph_fixture.py"))
    graph = module["project"](module["snapshot_token_mounted"](), module["image_scan_report"]())
    dates = {record["observed_at"] for node in graph["nodes"] for record in node["attributes"].get("attribute_observations", {}).values()}
    assert dates == {"2026-11-01T00:00:00+00:00"}
