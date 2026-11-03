"""A pom.xml-only Maven inventory states that transitive dependencies were not resolved.

pom.xml lists direct dependencies only; Maven resolves the rest at build time.
Without a note, a clean Maven result read as full dependency coverage.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.coverage import is_scan_note
from agent_bom.parsers.maven_packages import parse_maven_packages
from agent_bom.scanners.state import capture_coverage_warnings

_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>a</groupId><artifactId>b</artifactId><version>1</version>
<dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>
<version>2.9.8</version></dependency></dependencies></project>
"""


def test_pom_inventory_records_direct_only_note(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(_POM, encoding="utf-8")
    with capture_coverage_warnings() as recorded:
        packages = parse_maven_packages(tmp_path)
    assert [p.name for p in packages] == ["com.fasterxml.jackson.core:jackson-databind"]
    notes = [w for w in recorded if is_scan_note(w) and w["reason"] == "maven_transitive_unresolved"]
    assert len(notes) == 1
    assert "transitive" in notes[0]["detail"]
    assert "1 direct" in notes[0]["detail"]
    assert str(tmp_path) not in notes[0]["detail"]


def test_no_note_without_dependencies(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
        "<groupId>a</groupId><artifactId>b</artifactId><version>1</version></project>",
        encoding="utf-8",
    )
    with capture_coverage_warnings() as recorded:
        assert parse_maven_packages(tmp_path) == []
    assert not [w for w in recorded if w.get("reason") == "maven_transitive_unresolved"]
