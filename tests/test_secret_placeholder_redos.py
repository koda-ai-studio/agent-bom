"""The placeholder matcher reads untrusted file content, so it must stay linear."""

from __future__ import annotations

import subprocess
import sys

import pytest

_PROBE = (
    "from agent_bom.scanners.secret_lines import is_placeholder_value;"
    "import sys; n=int(sys.argv[1]); print(is_placeholder_value('changeme' + '0' * n + '!'))"
)


@pytest.mark.parametrize("n", [5_000])
def test_placeholder_match_is_linear_on_long_digit_runs(n: int) -> None:
    result = subprocess.run([sys.executable, "-c", _PROBE, str(n)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


@pytest.mark.parametrize("value", ["changeme", "changeme123", "changeme_changeme", "replaceme-2", "CHANGEME.changeme.7"])
def test_changeme_placeholders_still_match(value: str) -> None:
    from agent_bom.scanners.secret_lines import is_placeholder_value

    assert is_placeholder_value(value)
