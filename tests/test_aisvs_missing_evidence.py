"""Missing network observations cannot satisfy exposure controls."""

from unittest.mock import patch

import pytest

from agent_bom.cloud.aisvs_benchmark import _check_ai_4_3, _check_ai_5_2, run_benchmark
from agent_bom.cloud.aws_cis_benchmark import CheckStatus


@pytest.mark.parametrize("check", [_check_ai_4_3, _check_ai_5_2])
def test_unknown_network_address_is_no_data(check):
    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", return_value=True),
        patch("agent_bom.cloud.aisvs_benchmark._local_ip", return_value=""),
    ):
        result = check()
    assert result.status is CheckStatus.NO_DATA
    assert "could not determine" in result.evidence.lower()
    assert "localhost only" not in result.evidence.lower()


def test_unknown_exposure_never_increases_report_pass_rate():
    with (
        patch("agent_bom.cloud.aisvs_benchmark._tcp_open", return_value=True),
        patch("agent_bom.cloud.aisvs_benchmark._local_ip", return_value=""),
    ):
        report = run_benchmark(checks=["AI-4.3", "AI-5.2"])
    payload = report.to_dict()
    assert payload["passed"] == 0
    assert payload["pass_rate"] == 0
    assert [row["status"] for row in payload["checks"]] == ["no_data", "no_data"]
