"""``section`` + ``limit`` must bound the response size, not just the item count."""

from __future__ import annotations

import json

from agent_bom.mcp_tools.scan_response import PAGE_MAX_CHARS, section_page


def _big_finding(i: int) -> dict:
    return {
        "id": f"finding-{i}",
        "severity": "high",
        "title": f"Finding {i}",
        "evidence": {"blob": "x" * 9000},
        "compliance_tags": {f"fw{j}": [f"C-{j}-{k}" for k in range(20)] for j in range(10)},
    }


def _report(n: int = 50) -> dict:
    return {"findings": [_big_finding(i) for i in range(n)]}


def _page(limit: int, offset: int = 0) -> tuple[dict, int]:
    page = section_page(_report(), result_id="r1", section="findings", offset=offset, limit=limit, max_chars=500_000)
    return page, len(json.dumps(page, separators=(",", ":")))


def test_limit_ten_of_large_findings_stays_within_the_page_budget() -> None:
    page, size = _page(10)
    assert size <= PAGE_MAX_CHARS
    assert len(page["items"]) == 10
    assert [item["id"] for item in page["items"]] == [f"finding-{i}" for i in range(10)]
    assert page["next_offset"] == 10
    compacted = page["items"][0]
    assert compacted["severity"] == "high"
    assert set(compacted["_omitted_fields"]) == {"evidence", "compliance_tags"}
    assert page["compacted_items"] == 10
    assert "limit=1" in page["hint"]


def test_limit_one_returns_the_full_item() -> None:
    page, size = _page(1, offset=3)
    (item,) = page["items"]
    assert item == _big_finding(3)
    assert "_omitted_fields" not in item
    assert size < 500_000


def test_small_items_are_untouched() -> None:
    report = {"findings": [{"id": str(i), "severity": "low"} for i in range(30)]}
    page = section_page(report, result_id="r", section="findings", offset=0, limit=25, max_chars=500_000)
    assert len(page["items"]) == 25
    assert "compacted_items" not in page
    assert all("_omitted_fields" not in item for item in page["items"])
