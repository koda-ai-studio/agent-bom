"""Fresh durable key records govern every request, including cached KDF hits."""

from datetime import datetime, timedelta, timezone

from agent_bom.api.auth import Role, create_api_key
from agent_bom.api.sqlite_key_store import SQLiteKeyStore


def test_sqlite_replicas_enforce_lifecycle_and_record_last_use(tmp_path):
    first = SQLiteKeyStore(str(tmp_path / "keys.db"))
    second = SQLiteKeyStore(str(tmp_path / "keys.db"))
    raw, key = create_api_key("test", Role.VIEWER)
    first.add(key)
    assert key.key_hash != raw and key.key_salt
    assert second.verify(raw).key_id == key.key_id
    assert first.get(key.key_id).last_used is not None
    first.remove(key.key_id)
    assert second.verify(raw) is None
    raw, key = create_api_key("expired", Role.VIEWER)
    key.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    first.add(key)
    assert second.verify(raw) is None
    raw, key = create_api_key("rotate", Role.VIEWER)
    first.add(key)
    assert second.verify(raw) is not None
    first.mark_rotating(
        key.key_id, replacement_key_id="replacement", overlap_until=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    )
    assert second.verify(raw) is None
