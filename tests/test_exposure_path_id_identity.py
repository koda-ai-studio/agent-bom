"""Two stored paths over the same hops but different relationships are distinct exposure paths on every surface."""

from __future__ import annotations

from agent_bom.graph.container import AttackPath


def _pair() -> tuple[AttackPath, AttackPath]:
    hops = ["agent:a", "cloud_resource:pii-bucket", "data_store:pii"]
    return (
        AttackPath(source=hops[0], target=hops[-1], hops=hops, edges=["uses", "exposed_to"]),
        AttackPath(source=hops[0], target=hops[-1], hops=hops, edges=["uses", "stores"]),
    )


def test_every_surface_gives_relationship_distinct_paths_distinct_identical_ids():
    from agent_bom.api.graph_presentation import _path_identity
    from agent_bom.graph.exposure import exposure_path_id
    from agent_bom.mcp_tools.finding_graph import _path_id

    first, second = _pair()
    assert exposure_path_id(first) != exposure_path_id(second)
    for path in (first, second):
        assert _path_identity(path) == _path_id(path) == exposure_path_id(path)


def test_exposure_path_payload_id_matches_the_shared_identity():
    from agent_bom.graph.exposure import _exposure_path_for_attack_path, exposure_path_id

    first, second = _pair()
    ids = {_exposure_path_for_attack_path(path, nodes_by_id={})["id"] for path in (first, second)}
    assert ids == {exposure_path_id(first), exposure_path_id(second)}


def test_a_legacy_path_without_relationships_keeps_its_hop_id():
    from agent_bom.graph.exposure import exposure_path_id

    path = AttackPath(source="a", target="c", hops=["a", "b", "c"])
    assert exposure_path_id(path) == "a::c::a->b->c"


def test_diff_highlights_key_paths_by_relationship_and_carry_the_shared_id():
    from agent_bom.graph.diff_view import new_attack_paths
    from agent_bom.graph.exposure import exposure_path_id

    first, second = _pair()
    added = new_attack_paths([first], [first, second], old_total=1, new_total=2, window=10)
    assert added["count"] == 1
    assert [row["exposure_path_id"] for row in added["top"]] == [exposure_path_id(second)]
