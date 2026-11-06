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
