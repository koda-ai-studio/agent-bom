"""A path is suppressed only when every occurrence it ends on is suppressed."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.api.attack_path_suppression import mark_suppressed_paths, path_suppressed, suppression_count_metadata


def test_a_path_needs_every_occurrence_suppressed() -> None:
    suppressed = frozenset({"a", "b"})
    assert path_suppressed(["a"], suppressed)
    assert path_suppressed(["a", "b"], suppressed)
    assert not path_suppressed(["a", "c"], suppressed)
    # A path with no recorded occurrence is never hidden by an exception.
    assert not path_suppressed([], suppressed)
    assert not path_suppressed(None, suppressed)


def test_page_marks_and_queue_counts_agree() -> None:
    suppressed = frozenset({"a"})
    rows = [{"finding_ids": ["a"]}, {"finding_ids": ["a", "b"]}, {"finding_ids": []}]
    assert mark_suppressed_paths(rows, suppressed) == 1
    assert [row["suppressed"] for row in rows] == [True, False, False]

    paths = [SimpleNamespace(finding_ids=row["finding_ids"]) for row in rows]
    from agent_bom.api.attack_path_suppression import count_suppressed

    metadata = suppression_count_metadata(count_suppressed(paths, suppressed), suppressed, total=3, complete=True)
    assert (metadata["suppressed_paths"], metadata["open_paths"], metadata["suppression_complete"]) == (1, 2, True)


def test_no_suppression_needs_no_enumeration_and_unknown_is_not_zero() -> None:
    assert suppression_count_metadata(None, frozenset(), total=7, complete=False)["open_paths"] == 7
    unknown = suppression_count_metadata(None, frozenset({"a"}), total=7, complete=False)
    assert unknown["suppressed_paths"] is None and unknown["open_paths"] is None
    assert unknown["suppression_complete"] is False
