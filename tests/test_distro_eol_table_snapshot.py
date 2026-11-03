"""The end-of-life table matches a recorded endoflife.date snapshot, offline.

``tests/fixtures/distro_eol/endoflife_date_snapshot.json`` holds the API records
for alpine-linux, debian, ubuntu and rhel retrieved on the date it names. Where a
vendor announcement disagrees with the API, the vendor date wins and the
override cites the announcement. Every snapshot release whose end of life had
passed on ``END_OF_LIFE_AS_OF`` must be in the table, and no table row may be a
forecast.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from agent_bom.core.distro_eol import _END_OF_LIFE, END_OF_LIFE_AS_OF

SNAPSHOT = json.loads((Path(__file__).parent / "fixtures" / "distro_eol" / "endoflife_date_snapshot.json").read_text())
_PREFIX = {"alpine-linux": "alpine:v", "debian": "debian:", "ubuntu": "ubuntu:", "rhel": "red hat:enterprise_linux:"}


def _api_end_dates() -> dict[str, date]:
    return {
        f"{_PREFIX[product]}{row['cycle']}": date.fromisoformat(row["eol"])
        for product, rows in SNAPSHOT["records"].items()
        for row in rows
        if isinstance(row["eol"], str)
    }


def _expected_end(key: str, api: dict[str, date]) -> date:
    override = SNAPSHOT["vendor_overrides"].get(key)
    return date.fromisoformat(override["ended"]) if override else api[key]


def test_snapshot_is_dated_on_the_table_as_of_date() -> None:
    assert date.fromisoformat(SNAPSHOT["retrieved"]) == END_OF_LIFE_AS_OF


def test_every_table_row_matches_the_snapshot_or_a_cited_vendor_override() -> None:
    api = _api_end_dates()
    assert {key: row.ended for key, row in _END_OF_LIFE.items()} == {key: _expected_end(key, api) for key in _END_OF_LIFE}


def test_every_passed_end_of_life_in_the_snapshot_is_in_the_table() -> None:
    api = _api_end_dates()
    passed = {key for key in api if _expected_end(key, api) <= END_OF_LIFE_AS_OF}
    assert passed == set(_END_OF_LIFE)


def test_no_row_is_a_forecast_and_overrides_cite_the_vendor() -> None:
    assert all(row.ended <= END_OF_LIFE_AS_OF for row in _END_OF_LIFE.values())
    for key, override in SNAPSHOT["vendor_overrides"].items():
        assert override["source"].startswith("https://") and override["ended"] != override["api_eol"]
        assert _END_OF_LIFE[key].source == override["source"]
