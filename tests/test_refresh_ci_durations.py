from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.refresh_ci_durations import main, seconds_from_junit, seconds_from_log

LOG = """\
2026-10-23T04:44:21.0000000Z created: 2/2 workers
2026-10-23T04:44:21.1000000Z 2 workers [4 items]
2026-10-23T04:44:23.1000000Z [gw0] [ 25%] PASSED tests/test_a.py::test_one
2026-10-23T04:44:22.1000000Z [gw1] [ 50%] SKIPPED tests/api/test_b.py::test_two[x]
2026-10-23T04:44:24.1000000Z tests/test_a.py::test_unreported_progress_line
2026-10-23T04:44:26.1000000Z [gw0] [ 75%] FAILED tests/test_a.py::test_three
2026-10-23T04:44:27.6000000Z [gw1] [100%] PASSED tests/api/test_b.py::test_four
"""

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest">
<testcase classname="tests.test_a" name="test_one" file="tests/test_a.py" time="1.25"/>
<testcase classname="tests.test_a" name="test_two" time="0.75"/>
<testcase classname="tests.api.test_b" name="test_three" time="2.0"><skipped/></testcase>
</testsuite></testsuites>
"""


def test_log_charges_each_worker_gap_to_the_test_that_ended_it(tmp_path: Path) -> None:
    log = tmp_path / "shard.log"
    log.write_text(LOG, encoding="utf-8")

    assert seconds_from_log(log) == pytest.approx({"tests/test_a.py": 5.0, "tests/api/test_b.py": 6.5})


def test_log_colour_codes_do_not_hide_results(tmp_path: Path) -> None:
    log = tmp_path / "shard.log"
    log.write_text(LOG.replace("PASSED", "\x1b[32mPASSED\x1b[0m"), encoding="utf-8")

    assert seconds_from_log(log) == pytest.approx({"tests/test_a.py": 5.0, "tests/api/test_b.py": 6.5})


def test_log_without_a_session_start_is_rejected(tmp_path: Path) -> None:
    log = tmp_path / "shard.log"
    log.write_text("2026-10-23T04:44:23.1000000Z [gw0] [ 25%] PASSED tests/test_a.py::test_one\n", encoding="utf-8")

    with pytest.raises(SystemExit):
        seconds_from_log(log)


def test_junit_sums_case_time_per_module(tmp_path: Path) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(JUNIT, encoding="utf-8")

    assert seconds_from_junit(report) == pytest.approx({"tests/test_a.py": 2.0, "tests/api/test_b.py": 2.0})


def test_refresh_merges_sources_and_writes_sorted_rounded_json(tmp_path: Path, monkeypatch) -> None:
    import sys

    log = tmp_path / "shard.log"
    log.write_text(LOG, encoding="utf-8")
    report = tmp_path / "junit.xml"
    report.write_text(JUNIT.replace("tests/test_a.py", "tests/test_c.py").replace("tests.test_a", "tests.test_c"), encoding="utf-8")
    out = tmp_path / "durations.json"
    monkeypatch.setattr(sys, "argv", ["refresh", "--log", str(log), "--junit", str(report), "--output", str(out)])

    assert main() == 0

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert list(payload["files"]) == sorted(payload["files"])
    assert payload["files"] == {"tests/api/test_b.py": 8.5, "tests/test_a.py": 5.0, "tests/test_c.py": 2.0}
