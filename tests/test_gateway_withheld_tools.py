"""Gateway-side memory of tools withheld for poisoned descriptions: tenant-scoped, TTL-bounded, size-bounded."""

from __future__ import annotations

from agent_bom.runtime.withheld_tools import MAX_WITHHELD_ENTRIES, WithheldToolRegistry


def test_withheld_tools_are_scoped_per_tenant_and_upstream():
    registry = WithheldToolRegistry()
    registry.update("tenant-a", "fs", withheld={"evil"}, clean={"ok"})
    assert registry.is_withheld("tenant-a", "fs", "evil")
    assert not registry.is_withheld("tenant-a", "fs", "ok")
    assert not registry.is_withheld("tenant-b", "fs", "evil")
    assert not registry.is_withheld("tenant-a", "other", "evil")


def test_clean_relisting_restores_a_tool_and_entries_expire():
    now = [1000.0]
    registry = WithheldToolRegistry(ttl_seconds=60, clock=lambda: now[0])
    registry.update("t", "fs", withheld={"evil"}, clean=set())
    registry.update("t", "fs", withheld=set(), clean={"evil"})
    assert not registry.is_withheld("t", "fs", "evil")
    registry.update("t", "fs", withheld={"evil"}, clean=set())
    now[0] += 59
    assert registry.is_withheld("t", "fs", "evil")
    now[0] += 2
    assert not registry.is_withheld("t", "fs", "evil")
    assert len(registry) == 0


def test_registry_is_bounded_and_evicts_the_oldest_entries():
    registry = WithheldToolRegistry()
    registry.update("t", "fs", withheld={f"tool-{i}" for i in range(MAX_WITHHELD_ENTRIES)}, clean=set())
    assert len(registry) == MAX_WITHHELD_ENTRIES
    registry.update("t", "fs", withheld={"newest"}, clean=set())
    assert len(registry) == MAX_WITHHELD_ENTRIES
    assert registry.is_withheld("t", "fs", "newest")
    assert sum(registry.is_withheld("t", "fs", f"tool-{i}") for i in range(MAX_WITHHELD_ENTRIES)) == MAX_WITHHELD_ENTRIES - 1


def test_oversized_names_are_ignored_not_stored():
    registry = WithheldToolRegistry()
    registry.update("t", "fs", withheld={"x" * 10_000}, clean=set())
    assert len(registry) == 0
