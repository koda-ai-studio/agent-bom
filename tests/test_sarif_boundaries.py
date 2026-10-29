"""Keep SARIF export owners below the hard file-size ceiling."""

from pathlib import Path

from agent_bom.output import sarif


def test_sarif_owners_do_not_require_file_ceiling_allowances():
    oversized = {
        path.name: len(path.read_text().splitlines())
        for path in Path(sarif.__file__).parent.glob("sarif*.py")
        if len(path.read_text().splitlines()) > 1000
    }
    assert oversized == {}, "Split SARIF responsibilities instead of adding file-size debt"
