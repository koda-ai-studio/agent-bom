"""The daily re-match persists operator-advisory and feed findings into the finding store."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from agent_bom.api import advisory_rematch as rematch
from agent_bom.api import compliance_hub_store
from agent_bom.api.storage.hub_memory import InMemoryComplianceHubStore
from agent_bom.db import schema
from tests.api.test_advisory_rematch import ADVISORY, LATER, NOW, _Feed, _feed_advisory, _job, env  # noqa: F401 - fixture


@pytest.fixture()
def hub(env, monkeypatch: pytest.MonkeyPatch, tmp_path):  # noqa: F811 - pytest fixture injection
    monkeypatch.setattr(schema, "DB_PATH", tmp_path / "absent" / "vulns.db")
    store = InMemoryComplianceHubStore()
    compliance_hub_store.set_compliance_hub_store(store)
    yield env, store
    compliance_hub_store.reset_compliance_hub_store()


def _open(store: InMemoryComplianceHubStore, tenant: str) -> dict[str, dict]:
    rows, _total, _cursor = store.list_current_page(tenant, limit=100, status="open")
    payloads = [row.get("payload") if isinstance(row.get("payload"), dict) else row for row in rows]
    return {f"{payload['cve_id']}|{payload['package']}": payload for payload in payloads}


def test_rematch_persists_both_provenances_tenant_scoped(hub) -> None:
    advisories, store = hub
    advisories.put("tenant-a", ADVISORY)
    status = rematch.run_tenant_rematch("tenant-a", feed_source=_Feed([_feed_advisory()]), now=NOW)
    assert status["status"] == "complete"
    rows = _open(store, "tenant-a")
    assert set(rows) == {"CVE-2026-109618|php", "GHSA-feed-0001|left-pad"}
    assert rows["CVE-2026-109618|php"]["advisory_source"] == "operator_advisory"
    assert rows["GHSA-feed-0001|left-pad"]["advisory_source"] == "feed"
    assert rows["GHSA-feed-0001|left-pad"]["fixed_version"] == "1.3.1"
    assert _open(store, "tenant-b") == {}
    assert advisories.get_rematch_state("tenant-a")["persisted_feed_ids"] == ["GHSA-feed-0001"]


def test_rescan_without_the_package_retires_on_the_next_run(hub) -> None:
    advisories, store = hub
    advisories.put("tenant-a", ADVISORY)
    rematch.run_tenant_rematch("tenant-a", feed_source=_Feed([]), now=NOW)
    assert "CVE-2026-109618|php" in _open(store, "tenant-a")
    from agent_bom.api.stores import _get_store

    _get_store().put(_job("tenant-a", "php", "8.3.36", completed="2026-10-23T00:01:00+00:00"))
    rematch.run_tenant_rematch("tenant-a", feed_source=_Feed([], modified=None), now=LATER)
    assert "CVE-2026-109618|php" not in _open(store, "tenant-a")
