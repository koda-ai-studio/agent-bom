from pathlib import Path

import pytest

from scripts.profile_graph_snapshot_storage import profile


def test_probe_preserves_full_history_through_restore_and_scopes_retention(tmp_path: Path) -> None:
    result = profile(tmp_path / "probe", snapshots=4, nodes=20)
    assert result.get("restored_exports") == result["original_exports"]
    assert len(result["original_exports"]) == 5
    assert result["purge"]["purged_count"] == 2
    assert all(item["tenant_id"] == "storage-probe" for item in result["purge"]["purged_snapshots"])
    retained = result["retained_exports"]
    assert set(retained) == {"storage-probe/retained-2", "storage-probe/retained-3", "foreign-probe/retained-0"}
    assert all(result["original_exports"][key] == value for key, value in retained.items())
    assert result["after_purge"]["nodes"] == 60
    assert result["after_vacuum"]["nodes"] == 60
    assert result["attribute_bytes"] > result["tenant_unique_attribute_bytes"]
    assert result["one_export_gzip_bytes"] < result["one_export_bytes"]


def test_probe_refuses_existing_directory_without_changing_it(tmp_path: Path) -> None:
    marker = tmp_path / "existing.db"
    marker.write_text("retained evidence")
    with pytest.raises(FileExistsError):
        profile(tmp_path, snapshots=4, nodes=20)
    assert marker.read_text() == "retained evidence"
    assert list(tmp_path.iterdir()) == [marker]


@pytest.mark.parametrize(("snapshots", "nodes"), [(0, 2), (201, 2), (2, 5001)])
def test_probe_refuses_unbounded_work_before_creating_files(tmp_path: Path, snapshots: int, nodes: int) -> None:
    output = tmp_path / "probe"
    with pytest.raises(ValueError):
        profile(output, snapshots=snapshots, nodes=nodes)
    assert not output.exists()
