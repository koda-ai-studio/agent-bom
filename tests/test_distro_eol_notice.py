"""End-of-life OS releases produce an explicit, dated, sourced scan note.

Alpine 3.14 stopped receiving fixes on 2023-05-01. Without a note, a scan of
an alpine:3.14 image read as ordinary coverage; a low count there is not a
clean bill of health. The note is informational (``scan_note``), so it never
flips a scan to partial on its own.
"""

from __future__ import annotations

from datetime import date

import pytest

from agent_bom.core.distro_eol import END_OF_LIFE_AS_OF, end_of_life_release
from agent_bom.coverage import detect_release_coverage_gaps, is_scan_note
from agent_bom.models import Package
from agent_bom.scanners.state import capture_coverage_warnings


def _pkg(eco: str, distro: str, version: str, name: str = "musl") -> Package:
    return Package(name=name, version="1.2.2-r3", ecosystem=eco, distro_name=distro, distro_version=version)


def _notes(packages: list[Package]) -> list[dict]:
    with capture_coverage_warnings() as recorded:
        detect_release_coverage_gaps(packages, conn=None)
    return [w for w in recorded if is_scan_note(w) and w["reason"] == "distro_end_of_life"]


def test_alpine_3_14_gets_an_end_of_life_note() -> None:
    [note] = _notes([_pkg("apk", "alpine", "3.14.10")])
    assert note["release"].endswith("alpine:v3.14")
    assert "2023-05-01" in note["detail"]
    assert "alpinelinux.org/releases" in note["detail"]
    assert "not a clean bill of health" in note["detail"]


def test_debian_10_gets_an_end_of_life_note() -> None:
    [note] = _notes([_pkg("deb", "debian", "10.13", name="openssl")])
    assert note["release"].endswith("debian:10")
    assert "2024-06-30" in note["detail"]


def test_supported_or_unknown_release_gets_no_note() -> None:
    assert _notes([_pkg("deb", "debian", "12.5", name="openssl")]) == []
    assert _notes([_pkg("apk", "alpine", "3.22.1")]) == []
    assert _notes([Package(name="requests", version="2.31.0", ecosystem="pypi")]) == []


def test_one_note_per_release_however_many_packages() -> None:
    packages = [_pkg("apk", "alpine", "3.14.10", name=f"p{i}") for i in range(20)]
    assert len(_notes(packages)) == 1


@pytest.mark.parametrize(
    "key, today, expected",
    [("alpine:v3.14", date(2023, 4, 30), False), ("alpine:v3.14", date(2023, 5, 1), True), ("ubuntu:18.04", END_OF_LIFE_AS_OF, True)],
)
def test_end_of_life_is_date_aware(key: str, today: date, expected: bool) -> None:
    assert (end_of_life_release(key, today=today) is not None) is expected
