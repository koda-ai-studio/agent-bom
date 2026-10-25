"""OCSF attribution survives normalization without inventing agent bindings."""

import pytest

from agent_bom.api.observability_events import _normalize_ocsf_event, _runtime_observation_from_event


def event(class_uid=6003):
    return {
        "class_uid": class_uid,
        "time": "2026-10-25T10:00:00Z",
        "metadata": {"uid": "event-1", "product": {"name": "collector"}},
        "actor": {"user": {"uid": "principal-1"}, "session": {"uid": "session-1"}},
        "cloud": {"account": {"uid": "account-1"}, "region": "us-east-1", "provider": "AWS"},
        "device": {"uid": "device-1", "hostname": "worker"},
    }


@pytest.mark.parametrize("class_uid", [2004, 6003])
def test_attribution_is_retained_in_durable_redacted_metadata(class_uid):
    normalized = _normalize_ocsf_event(event(class_uid), tenant_id="tenant-a")
    record = _runtime_observation_from_event(normalized, tenant_id="tenant-a")
    assert record.metadata["cloud"]["account"]["uid"] == "account-1"
    assert record.metadata["cloud"]["region"] == "us-east-1"
    assert record.metadata["device"]["hostname"] == "worker"
    assert record.metadata["actor"]["user"]["uid_hash"].startswith(("h1:", "h1w:"))
    assert "principal-1" not in repr(record)
    assert record.agent_name == ""  # an OCSF user is not necessarily an AI agent


def test_replay_session_is_stable_and_tenant_account_source_scoped():
    raw = event()
    first = _normalize_ocsf_event(raw, tenant_id="a")
    again = _normalize_ocsf_event(raw, tenant_id="a")
    assert first["session_id"] == again["session_id"] != ""
    assert first["session_id"] != _normalize_ocsf_event(raw, tenant_id="b")["session_id"]
    raw["cloud"]["account"]["uid"] = "account-2"
    assert first["session_id"] != _normalize_ocsf_event(raw, tenant_id="a")["session_id"]
    raw["cloud"]["account"]["uid"] = "account-1"
    raw["metadata"]["product"]["name"] = "other"
    assert first["session_id"] != _normalize_ocsf_event(raw, tenant_id="a")["session_id"]


def test_missing_session_uses_event_identity_without_linking_unrelated_events():
    raw = event()
    raw.pop("actor")
    first = _normalize_ocsf_event(raw, tenant_id="a")
    records = [_runtime_observation_from_event(first, tenant_id="a") for _ in range(2)]
    assert records[0].session_id == records[1].session_id
    raw["metadata"]["uid"] = "event-2"
    other = _runtime_observation_from_event(_normalize_ocsf_event(raw, tenant_id="a"), tenant_id="a")
    assert records[0].session_id != other.session_id


def test_actor_context_is_allowlisted_bounded_and_does_not_copy_payloads():
    raw = event()
    raw["actor"]["session"]["token"] = "private-test-value"
    raw["actor"]["user"]["email_addr"] = "private@example.invalid"
    raw["device"]["hostname"] = "h" * 2000
    raw["device"]["raw"] = "private-test-value"
    record = _runtime_observation_from_event(_normalize_ocsf_event(raw, tenant_id="a"), tenant_id="a")
    assert "private-test-value" not in repr(record)
    assert "private@example.invalid" not in repr(record)
    assert len(record.metadata["device"]["hostname"]) <= 200


@pytest.mark.parametrize("field", ["account", "session"])
def test_long_identity_suffixes_do_not_collapse_sessions(field):
    raw = event()
    target = raw["cloud"]["account"] if field == "account" else raw["actor"]["session"]
    target["uid"] = "x" * 200 + "one"
    first = _normalize_ocsf_event(raw, tenant_id="a")
    target["uid"] = "x" * 200 + "two"
    assert first["session_id"] != _normalize_ocsf_event(raw, tenant_id="a")["session_id"]


def test_idless_untimed_event_replay_does_not_invent_a_new_session(monkeypatch):
    from agent_bom.api import observability_events

    raw = event()
    raw.pop("time")
    raw.pop("actor")
    raw["metadata"].pop("uid")
    monkeypatch.setattr(observability_events, "_now", lambda: "2026-10-25T10:00:00Z")
    first = _normalize_ocsf_event(raw, tenant_id="a")
    monkeypatch.setattr(observability_events, "_now", lambda: "2026-10-25T11:00:00Z")
    replay = _normalize_ocsf_event(raw, tenant_id="a")
    assert first["session_id"] == replay["session_id"]
    assert first["timestamp_basis"] == "receipt"
