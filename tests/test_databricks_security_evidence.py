"""Security verdicts require direct evidence from the relevant workspace scope."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.cloud.databricks_security import _check_1_3, _check_1_4, _check_2_4, _check_4_1


@pytest.mark.parametrize(
    "days,status", [("90", "pass"), ("1", "pass"), ("91", "fail"), ("0", "fail"), (None, "error"), ("garbage", "error")]
)
def test_pat_policy_uses_supported_workspace_configuration(days, status):
    ws = SimpleNamespace(workspace_conf=SimpleNamespace(get_status=Mock(return_value={"maxTokenLifetimeDays": days})))
    result = _check_1_3(ws)
    assert result.status.value == status
    ws.workspace_conf.get_status.assert_called_once_with(keys="maxTokenLifetimeDays")


@pytest.mark.parametrize("expiry,status", [(-1, "fail"), (0, "fail"), (None, "error"), ("invalid", "error")])
def test_service_principal_nonexpiring_or_unknown_token_is_not_clean(expiry, status):
    ws = SimpleNamespace(
        service_principals=SimpleNamespace(list=lambda: [SimpleNamespace(id="7")]),
        token_management=SimpleNamespace(list=lambda: [SimpleNamespace(owner_id=7, expiry_time=expiry)]),
    )
    assert _check_1_4(ws).status.value == status


def test_other_users_tokens_are_not_attributed_to_service_principals():
    ws = SimpleNamespace(
        service_principals=SimpleNamespace(list=lambda: [SimpleNamespace(id="7")]),
        token_management=SimpleNamespace(list=lambda: [SimpleNamespace(owner_id=8, expiry_time=9999999999999)]),
    )
    result = _check_1_4(ws)
    assert result.status.value == "pass"
    assert "enumerated" in result.evidence


def test_missing_token_owner_is_an_evidence_gap():
    ws = SimpleNamespace(
        service_principals=SimpleNamespace(list=lambda: [SimpleNamespace(id="7")]),
        token_management=SimpleNamespace(list=lambda: [SimpleNamespace(expiry_time=9999999999999)]),
    )
    assert _check_1_4(ws).status.value == "error"


def test_disk_configuration_does_not_prove_private_networking():
    cluster = SimpleNamespace(
        cluster_id="fixture", state="RUNNING", enable_elastic_disk=True, aws_attributes=SimpleNamespace(ebs_volume_count=1)
    )
    assert _check_2_4(SimpleNamespace(clusters=SimpleNamespace(list=lambda: [cluster]))).status.value == "error"


def test_billable_usage_delivery_is_not_audit_log_delivery():
    ws = SimpleNamespace(log_delivery=SimpleNamespace(list=lambda: [SimpleNamespace(log_type="BILLABLE_USAGE", status="ENABLED")]))
    assert _check_4_1(ws).status.value != "pass"


def test_sdk_enums_do_not_hide_running_unsafe_clusters():
    from enum import Enum
    from agent_bom.cloud.databricks_security import _check_2_2

    class State(Enum):
        RUNNING = "RUNNING"

    class Mode(Enum):
        NONE = "NONE"

    cluster = SimpleNamespace(cluster_id="fixture", state=State.RUNNING, data_security_mode=Mode.NONE)
    assert _check_2_2(SimpleNamespace(clusters=SimpleNamespace(list=lambda: [cluster]))).status.value == "fail"


def test_sdk_job_source_enum_is_excluded_from_interactive_checks():
    from enum import Enum
    from agent_bom.cloud.databricks_security import _check_2_1

    class Source(Enum):
        JOB = "JOB"

    cluster = SimpleNamespace(cluster_id="fixture", cluster_source=Source.JOB, auto_termination_minutes=0)
    assert _check_2_1(SimpleNamespace(clusters=SimpleNamespace(list=lambda: [cluster]))).status.value == "pass"


def test_unknown_cluster_isolation_is_not_a_clean_verdict():
    from agent_bom.cloud.databricks_security import _check_2_2

    cluster = SimpleNamespace(cluster_id="fixture", state="RUNNING", data_security_mode="NEW_UNKNOWN_MODE")
    assert _check_2_2(SimpleNamespace(clusters=SimpleNamespace(list=lambda: [cluster]))).status.value == "error"
