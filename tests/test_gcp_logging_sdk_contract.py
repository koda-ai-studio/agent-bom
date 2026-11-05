"""GCP logging checks use the generated clients exposed by Logging SDK 3.x."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.cloud import gcp_cis_benchmark as benchmark
from agent_bom.cloud.gcp_cis import _base


@pytest.mark.parametrize("number", range(2, 12))
def test_logging_checks_use_service_modules_and_preserve_credentials(monkeypatch, number):
    client = Mock()
    client.list_sinks.return_value = []
    client.list_log_metrics.return_value = []
    factory = Mock(return_value=client)
    modules = {
        "logging_v2": SimpleNamespace(),
        "logging_v2.services.config_service_v2": SimpleNamespace(ConfigServiceV2Client=factory),
        "logging_v2.services.metrics_service_v2": SimpleNamespace(MetricsServiceV2Client=factory),
    }
    monkeypatch.setattr(benchmark, "_import_google_cloud_module", modules.__getitem__)
    credentials = object()
    _base._set_credentials(credentials)
    try:
        result = getattr(benchmark, f"_check_2_{number}")("fixture-project")
    finally:
        _base._clear_credentials()
    assert result.status == benchmark.CheckStatus.FAIL
    assert result.check_id == f"2.{number}"
    factory.assert_called_once_with(credentials=credentials)
    method = client.list_sinks if number == 2 else client.list_log_metrics
    method.assert_called_once_with(parent="projects/fixture-project")


@pytest.mark.parametrize("number", range(2, 12))
def test_logging_provider_errors_remain_errors(monkeypatch, number):
    def unavailable(_):
        raise PermissionError("fixture permission denied")

    monkeypatch.setattr(benchmark, "_import_google_cloud_module", unavailable)
    result = getattr(benchmark, f"_check_2_{number}")("fixture-project")
    assert result.status == benchmark.CheckStatus.ERROR


@pytest.mark.parametrize("reason", ["SERVICE_DISABLED", "BILLING_DISABLED"])
@pytest.mark.parametrize("check", ["_check_2_2", "_check_3_1", "_check_4_1", "_check_5_2"])
def test_disabled_provider_api_is_unevaluated_not_a_scanner_error(monkeypatch, reason, check):
    class DisabledAPIError(Exception):
        pass

    exc = DisabledAPIError("fixture-provider-detail")
    exc.reason = reason

    def unavailable(_):
        raise exc

    monkeypatch.setattr(benchmark, "_import_google_cloud_module", unavailable)
    result = getattr(benchmark, check)("fixture-project")
    assert result.status == benchmark.CheckStatus.NO_DATA
    assert "disabled" in result.evidence.lower()
    assert "fixture-provider-detail" not in result.evidence
    assert "grant" not in result.evidence.lower()
