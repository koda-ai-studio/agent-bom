"""The performance lane's opt-in stack sampler stays off by default and records only frame names when on."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

QUALIFICATION = Path(__file__).resolve().parents[1] / "scripts" / "qualification"
sys.path.insert(0, str(QUALIFICATION))

import performance  # noqa: E402

_SECRET = "s3cr3t-local-value"
_CHILD = (
    "import time\n"
    "from agent_bom.core import background_yield\n"
    "background_yield.register_request_probe(lambda: True)\n"
    "def hold(secret):\n"
    "    deadline = time.monotonic() + 1.5\n"
    "    with background_yield.background_work():\n"
    "        while time.monotonic() < deadline:\n"
    "            background_yield.pause_for_requests()\n"
    f"hold({_SECRET!r})\n"
)


def test_sampler_is_off_unless_asked(monkeypatch) -> None:
    monkeypatch.delenv("QUALIFICATION_STACK_SAMPLES", raising=False)
    env = {"PATH": "/bin", "QUALIFICATION_STACK_SAMPLES": "0"}
    assert performance.api_environment(env, "estate") is env
    assert performance.api_environment({"PATH": "/bin"}, "estate") == {"PATH": "/bin"}


def test_sampler_loads_ahead_of_the_existing_path(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(performance, "RESULTS_DIR", tmp_path)
    env = performance.api_environment({"PYTHONPATH": "/existing", "QUALIFICATION_STACK_SAMPLES": "1"}, "agents-5000")
    assert env["PYTHONPATH"].split(":") == [str(performance.STACK_SAMPLER_DIR), "/existing"]
    assert env["QUALIFICATION_STACK_FILE"] == str(tmp_path / "stacks" / "api-agents-5000")
    assert (tmp_path / "stacks").is_dir()


def test_sampler_records_agent_bom_frames_without_values(monkeypatch, tmp_path: Path) -> None:
    import os

    monkeypatch.setattr(performance, "RESULTS_DIR", tmp_path)
    env = performance.api_environment({**os.environ, "QUALIFICATION_STACK_SAMPLES": "1"}, "child")
    child = subprocess.run([sys.executable, "-c", _CHILD], env=env, timeout=60, check=True)  # noqa: S603
    assert child.returncode == 0
    files = list((tmp_path / "stacks").glob("api-child.*.tsv"))
    assert len(files) == 1, files
    deadline = time.monotonic() + 5
    rows: list[list[str]] = []
    while time.monotonic() < deadline and not rows:
        rows = [line.split("\t") for line in files[0].read_text(encoding="utf-8").splitlines()]
    assert rows, "no samples written"
    assert all(len(row) == 3 and float(row[0]) > 0 for row in rows)
    assert any("background_yield:pause_for_requests:" in row[2] for row in rows), rows[:3]
    assert _SECRET not in files[0].read_text(encoding="utf-8")
