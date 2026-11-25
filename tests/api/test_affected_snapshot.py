"""One investigation answer must not combine different graph revisions."""

from unittest.mock import Mock

import pytest

from agent_bom.api.affected_read import _story_reach


@pytest.fixture
def store(monkeypatch):
    value = Mock()
    value.snapshot_identity.return_value = ("snapshot-a", "generation-a")
    monkeypatch.setattr("agent_bom.api.stores._get_graph_store", lambda: value)
    return value


def story(scan="snapshot-a", generation="generation-a", *, complete=True, listed=True):
    return {
        "scan_id": scan,
        "snapshot_generation": generation,
        "at_risk": {
            "groups": [{"kind": "credentials", "items": [{"id": f"cred:{scan}", "label": scan}]}],
            "listed_complete": listed,
            "completeness": {"complete": complete},
        },
    }


def test_every_advisory_uses_the_original_snapshot(store, monkeypatch):
    reads = []

    def read(_store, *, tenant_id, scan_id, **kwargs):
        reads.append((tenant_id, scan_id))
        return story(scan=scan_id or f"moving-{len(reads)}")

    monkeypatch.setattr("agent_bom.graph.exploit_story_read.read_exploit_story", read)
    result = _story_reach("tenant-a", ["CVE-2026-1000", "CVE-2026-2000"])
    assert reads == [("tenant-a", "snapshot-a"), ("tenant-a", "snapshot-a")]
    assert result["by_kind"] == {"credentials": 1}
    assert result["snapshot_generation"] == "generation-a"
    assert result["complete"] is True
    assert result["direction"] == "outbound"


@pytest.mark.parametrize("drift", ["between_stories", "after_read"])
def test_generation_change_discards_the_entire_reach_answer(store, monkeypatch, drift):
    reader = Mock(side_effect=[story(), story(generation="generation-b" if drift == "between_stories" else "generation-a")])
    if drift == "after_read":
        store.snapshot_identity.side_effect = [("snapshot-a", "generation-a"), ("snapshot-a", "generation-b")]
    monkeypatch.setattr("agent_bom.graph.exploit_story_read.read_exploit_story", reader)
    result = _story_reach("tenant-a", ["CVE-2026-1000", "CVE-2026-2000"])
    assert result["basis"] == "unavailable"
    assert result["items"] == {} and result["advisories_walked"] == []
    assert result["scan_id"] is None and result["complete"] is False
    assert "snapshot_changed" in result["reasons"]


@pytest.mark.parametrize(("complete", "listed", "reason"), [(False, True, "traversal_limit"), (True, False, "item_limit")])
def test_story_limits_are_not_lost_in_aggregate_counts(store, monkeypatch, complete, listed, reason):
    monkeypatch.setattr("agent_bom.graph.exploit_story_read.read_exploit_story", Mock(return_value=story(complete=complete, listed=listed)))
    result = _story_reach("tenant-a", ["CVE-2026-1000"])
    assert result["complete"] is False and result["truncated"] is True
    assert reason in result["reasons"]
    assert result["by_kind"] == {"credentials": 1}


def test_backend_failure_does_not_keep_a_successful_prefix_or_hide_behind_cap(store, monkeypatch):
    monkeypatch.setattr("agent_bom.api.affected_read.MAX_STORIES", 2)
    monkeypatch.setattr(
        "agent_bom.graph.exploit_story_read.read_exploit_story", Mock(side_effect=[story(), RuntimeError("backend unavailable")])
    )
    result = _story_reach("tenant-a", ["CVE-2026-1000", "CVE-2026-2000", "CVE-2026-3000"])
    assert result["items"] == {} and result["basis"] == "unavailable"
    assert set(result["reasons"]) == {"advisory_limit", "read_unavailable"}
    assert "unavailable" in result["note"] and "first 2 of 3" in result["note"]


def test_empty_query_does_not_open_a_graph_store(store):
    result = _story_reach("tenant-a", [])
    store.snapshot_identity.assert_not_called()
    assert result["complete"] is False and result["basis"] == "findings_only"


def test_findings_walk_limit_marks_reach_incomplete(store, monkeypatch):
    from agent_bom.api import affected_read

    monkeypatch.setattr(affected_read, "_walk", lambda *_: ([{"cve_id": "CVE-2026-1000"}], True))
    monkeypatch.setattr(affected_read, "_inventory", lambda *_: {"available": False})
    monkeypatch.setattr("agent_bom.graph.exploit_story_read.read_exploit_story", Mock(return_value=story()))
    answer = affected_read.read_affected(None, "tenant-a", "CVE-2026-1000")
    assert answer["reach"]["complete"] is False
    assert "findings_limit" in answer["reach"]["reasons"]


def test_empty_findings_keep_the_same_reach_contract_for_mcp(store, monkeypatch):
    from agent_bom.api import affected_read

    monkeypatch.setattr(affected_read, "_walk", lambda *_: ([], False))
    monkeypatch.setattr(affected_read, "_inventory", lambda *_: {"available": False})
    answer = affected_read.read_affected(None, "tenant-a", "CVE-2026-1000")
    assert answer["reach"]["complete"] is False
    assert answer["reach"]["snapshot_generation"] is None


def test_cli_surfaces_partial_outbound_reach_and_does_not_call_no_match_clean():
    from agent_bom.cli._findings_group import _affected_summary

    result = _affected_summary(
        {
            "verdict": "affected",
            "query": {"raw": "example"},
            "reach": {"by_kind": {"credentials": 1}, "complete": False, "note": "Traversal limit reached."},
        }
    )
    assert "Outbound reach (listed)" in result
    assert "Traversal limit reached." in result
    result = _affected_summary({"verdict": "not_found", "query": {"raw": "example"}, "reach": {"note": "Findings limit reached."}})
    assert "No match found" in result
    assert "Not affected" not in result
    assert "Findings limit reached." in result


def test_real_sqlite_reach_is_tenant_scoped_and_generation_bound(tmp_path, monkeypatch):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from tests.test_exploit_story import story_graph

    db = SQLiteGraphStore(tmp_path / "reach.db")
    for tenant in ("tenant-a", "tenant-b"):
        graph = story_graph()
        graph.tenant_id = tenant
        graph.nodes["cred:openai"].label = tenant
        db.save_graph(graph)
    monkeypatch.setattr("agent_bom.api.stores._get_graph_store", lambda: db)
    for tenant in ("tenant-a", "tenant-b"):
        reach = _story_reach(tenant, ["CVE-2023-0001"])
        assert reach["basis"] == "graph_snapshot" and reach["complete"] is True
        assert (reach["scan_id"], reach["snapshot_generation"]) == db.snapshot_identity(tenant_id=tenant, for_paging=True)
        credential = next(item for item in reach["items"]["credentials"] if item["id"] == "cred:openai")
        assert credential["label"] == tenant


def test_real_sqlite_replacement_between_reads_cannot_mix_generations(tmp_path, monkeypatch):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph import exploit_story_read
    from tests.test_exploit_story import story_graph

    db = SQLiteGraphStore(tmp_path / "reach.db")
    graph = story_graph()
    db.save_graph(graph)
    read = exploit_story_read.read_exploit_story
    calls = 0

    def replace_after_read(*args, **kwargs):
        nonlocal calls
        result = read(*args, **kwargs)
        calls += 1
        if calls == 1:
            graph.nodes["cred:openai"].label = "changed"
            db.save_graph(graph)
        return result

    monkeypatch.setattr("agent_bom.api.stores._get_graph_store", lambda: db)
    monkeypatch.setattr(exploit_story_read, "read_exploit_story", replace_after_read)
    reach = _story_reach("tenant-a", ["CVE-2023-0001", "CVE-2023-0001"])
    assert reach["basis"] == "unavailable" and not reach["items"]
    assert "snapshot_changed" in reach["reasons"]


def test_previous_match_does_not_claim_all_findings_were_resolved() -> None:
    from agent_bom.cli._findings_group import _affected_summary

    result = _affected_summary(
        {
            "verdict": "previously_affected",
            "query": {"raw": "example"},
            "findings": {"total": 1, "open": 0, "resolved": 0, "suppressed": 1},
        }
    )
    assert "all resolved" not in result.lower()
    assert "0 resolved" in result
