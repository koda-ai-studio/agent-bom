"""The screenshot/demo advisory-source fixture matches the product's source catalog."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_intel_sources_fixture_is_current():
    result = subprocess.run(
        [sys.executable, str(ROOT / "ui/scripts/generate-intel-sources-fixture.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
