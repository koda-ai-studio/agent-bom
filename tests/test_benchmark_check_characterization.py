"""Frozen benchmark results across successful, missing and failed provider reads."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud import aws_cis_benchmark as aws
from agent_bom.cloud.gcp_cis import cloudsql

FIXTURE = Path(__file__).parent / "fixtures" / "benchmark_check_results.json"


def benchmark_results():
    results = {}
    patterns = (
        "UnauthorizedAccess AccessDenied ConsoleLogin MFAUsed Failed userIdentity.type Root "
        "DeleteGroupPolicy DeleteRolePolicy DeleteUserPolicy CreateTrail UpdateTrail DeleteTrail "
        "DisableKey ScheduleKeyDeletion PutBucketAcl PutBucketPolicy PutBucketCors "
        "StopConfigurationRecorder DeleteDeliveryChannel AuthorizeSecurityGroupIngress "
        "AuthorizeSecurityGroupEgress RevokeSecurityGroupIngress CreateNetworkAcl CreateNetworkAclEntry "
        "DeleteNetworkAcl CreateCustomerGateway DeleteCustomerGateway AttachInternetGateway "
        "CreateRoute CreateRouteTable ReplaceRoute CreateVpc DeleteVpc ModifyVpcAttribute "
        "InviteAccountToOrganization LeaveOrganization"
    )
    for scenario in ("empty", "unmatched", "no_transform", "no_alarm", "pass", "read_error", "alarm_error"):
        logs, alarms, trails = MagicMock(), MagicMock(), MagicMock()
        metric = {"filterPattern": patterns if scenario != "unmatched" else "unrelated"}
        if scenario != "no_transform":
            metric["metricTransformations"] = [{"metricName": "metric", "metricNamespace": "namespace"}]
        logs.get_paginator.return_value.paginate.return_value = [
            {"metricFilters": []},
            {"metricFilters": [] if scenario == "empty" else [metric]},
        ]
        alarms.describe_alarms_for_metric.return_value = {"MetricAlarms": [] if scenario == "no_alarm" else [{}]}
        trails.describe_trails.return_value = {"trailList": [{"CloudWatchLogsLogGroupArn": "fixture-log-group"}]}
        if scenario == "read_error":
            logs.get_paginator.side_effect = RuntimeError("provider unavailable")
        if scenario == "alarm_error":
            alarms.describe_alarms_for_metric.side_effect = RuntimeError("provider unavailable")
        for number in range(1, 16):
            args = (logs, trails, alarms) if number == 5 else (logs, alarms)
            results[f"aws-4.{number}-{scenario}"] = asdict(getattr(aws, f"_check_4_{number}")(*args))
    good = {
        "name": "good",
        "databaseVersion": "POSTGRES_15",
        "settings": {
            "ipConfiguration": {"requireSsl": True},
            "backupConfiguration": {"enabled": True},
            "databaseFlags": [
                {"name": k, "value": v}
                for k, v in (
                    ("log_error_verbosity", "DEFAULT"),
                    ("log_connections", "ON"),
                    ("log_disconnections", "on"),
                    ("log_min_duration_statement", "-1"),
                )
            ],
        },
    }
    bad = {"name": "bad", "databaseVersion": "POSTGRES_15", "ipAddresses": [{"type": "PRIMARY"}]}
    for scenario, instances in {
        "empty": [],
        "malformed_name": [{**bad, "name": 1}],
        "list_flag": [{**good, "settings": {"databaseFlags": [{"name": "log_min_duration_statement", "value": []}]}}],
        "null_flags": [
            {
                **good,
                "settings": {
                    "databaseFlags": [
                        {"name": key, "value": None}
                        for key in ("log_error_verbosity", "log_connections", "log_disconnections", "log_min_duration_statement")
                    ]
                },
            }
        ],
        "numeric_flags": [
            {
                **good,
                "settings": {
                    "databaseFlags": [
                        {"name": key, "value": -1}
                        for key in ("log_error_verbosity", "log_connections", "log_disconnections", "log_min_duration_statement")
                    ]
                },
            }
        ],
        "duplicate_flags": [
            {
                **good,
                "settings": {"databaseFlags": [{"name": "log_connections", "value": "off"}, {"name": "log_connections", "value": "on"}]},
            }
        ],
        "malformed_settings": [{**good, "settings": None}],
        "missing_name": [{"databaseVersion": "POSTGRES_15"}],
        "good": [good],
        "bad": [bad],
        "mixed": [good, bad],
        "mysql": [{**bad, "databaseVersion": "MYSQL_8_0"}],
        "many": [{**bad, "name": f"bad-{i}"} for i in range(12)],
        "missing_sdk": ImportError(),
        "read_error": RuntimeError("provider unavailable"),
    }.items():
        with patch.object(cloudsql, "_gcp_cloud_sql_instances") as read:
            if isinstance(instances, Exception):
                read.side_effect = instances
            else:
                read.return_value = instances
            for number in range(1, 8):
                results[f"gcp-6.{number}-{scenario}"] = asdict(getattr(cloudsql, f"_check_6_{number}")("fixture-project"))
    catalog = {}
    outcomes = {}
    for key, result in results.items():
        check = "-".join(key.split("-")[:2])
        outcome = {field: result.pop(field) for field in ("status", "evidence", "resource_ids")}
        if check in catalog:
            assert catalog[check] == result
        catalog[check] = result
        outcomes[key] = outcome
    return {"checks": catalog, "outcomes": outcomes}


def test_benchmark_results_match_frozen_contract():
    assert benchmark_results() == json.loads(FIXTURE.read_text())


@pytest.mark.parametrize("number", [1, 2, 6, 7, 8, 9, 10, 11, 12, 13, 14])
def test_metric_filter_errors_redact_credentials(number):
    logs = MagicMock()
    logs.get_paginator.side_effect = RuntimeError("https://user:private-password@example.invalid?token=private-token")
    result = getattr(aws, f"_check_4_{number}")(logs, MagicMock())
    assert result.status == aws.CheckStatus.ERROR
    assert "private-password" not in result.evidence
    assert "private-token" not in result.evidence
