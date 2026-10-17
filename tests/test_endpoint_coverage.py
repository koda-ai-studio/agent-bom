"""Coverage denominators distinguish a returned page from a complete fleet."""

from agent_bom.connectors.endpoints.models import SyncState
from agent_bom.connectors.endpoints.service import device_page
from agent_bom.device_posture import DeviceSignal


class Store:
    def get(self, *args):
        return object()

    def latest(self, *args):
        return SyncState(
            run_id="run",
            connection_id="c",
            tenant_id="a",
            started_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            status="partial",
            device_count=50,
            expected_count=100,
            gap="permission_denied",
        )

    def devices(self, *args, **kwargs):
        return [
            DeviceSignal(tenant_id="a", device_id="stale", source="jamf", last_seen="2020-01-01T00:00:00Z"),
            DeviceSignal(tenant_id="a", device_id="unknown", source="jamf"),
        ]

    def bindings_for_devices(self, *args):
        return {"stale": [{"active": True}], "unknown": [{"active": False}]}

    def history(self, *args):
        return []


def test_coverage_is_page_scoped_and_retired_bindings_do_not_count():
    result = device_page(Store(), "a", "c", limit=2, offset=10)
    assert result["coverage"] == {
        "expected_devices": 100,
        "observed_devices": 50,
        "not_observed_devices": 50,
        "page_devices": 2,
        "page_stale_devices": 1,
        "page_unknown_freshness_devices": 1,
        "page_unbound_devices": 1,
        "collection_status": "partial",
        "collection_gap": "permission_denied",
    }


def test_not_collected_denominator_stays_unknown():
    store = Store()
    store.latest = lambda *args: None
    result = device_page(store, "a", "c")
    assert result["coverage"]["expected_devices"] is None
    assert result["coverage"]["not_observed_devices"] is None
    assert result["coverage"]["collection_status"] == "not_started"
    assert result["coverage"]["page_devices"] == 0
