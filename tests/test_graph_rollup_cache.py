"""Retention bounds apply to serialized summaries, not full graph objects."""

from agent_bom.api import graph_rollup_cache as cache


def test_retention_is_bounded_and_returns_independent_payloads(monkeypatch):
    monkeypatch.setattr(cache, "_CACHE", cache.OrderedDict())
    monkeypatch.setattr(cache, "_MAX_ENTRIES", 2)
    for i in range(3):
        cache.put((i,), {"count": i})
    assert cache.get((0,)) is None
    returned = cache.get((1,))
    returned["count"] = 99
    assert cache.get((1,)) == {"count": 1}


def test_expiry_and_byte_eviction(monkeypatch):
    monkeypatch.setattr(cache, "_CACHE", cache.OrderedDict())
    monkeypatch.setattr(cache, "_MAX_BYTES", 32)
    cache.put(("a",), {"value": "a" * 10})
    cache.put(("b",), {"value": "b" * 10})
    assert cache.get(("a",)) is None
    assert cache.get(("b",))
    monkeypatch.setattr(cache.time, "monotonic", lambda: float("inf"))
    assert cache.get(("b",)) is None


def test_estate_scale_summary_is_retained_compressed(monkeypatch):
    """A 100k-node roll-up body is MBs of repetitive JSON; it must still cache."""
    monkeypatch.setattr(cache, "_CACHE", cache.OrderedDict())
    entries = [
        {"id": f"agent:agent-{i:05d}", "aggregate": {"severity_counts": {"critical": i % 3, "high": 1}, "by_type": {"server": 2}}}
        for i in range(12_000)
    ]
    payload = {"top_level": entries}
    assert len(cache.json.dumps(payload)) > 1_000_000
    cache.put(("estate",), payload)
    assert cache.get(("estate",)) == payload


def test_incompressible_oversized_summary_is_not_retained(monkeypatch):
    import os

    monkeypatch.setattr(cache, "_CACHE", cache.OrderedDict())
    cache.put(("random",), {"text": os.urandom(cache._MAX_ENTRY_BYTES).hex()})
    assert cache.get(("random",)) is None
