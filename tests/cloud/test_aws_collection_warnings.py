"""AWS collection failures are classified, fixed-text warnings that keep going."""

from unittest.mock import MagicMock

import pytest

botocore_exceptions = pytest.importorskip("botocore.exceptions")
ClientError = botocore_exceptions.ClientError

from agent_bom.cloud import aws, aws_compute  # noqa: E402
from agent_bom.cloud.aws_errors import AWS_THROTTLED_CODES, aws_read_status, aws_read_warning  # noqa: E402
from agent_bom.cloud.collection_errors import CollectionStatus  # noqa: E402

PRIVATE = "arn:aws:iam::123456789012:user/private-marker"


def client_error(code, op="Op"):
    return ClientError({"Error": {"Code": code, "Message": f"User {PRIVATE} not authorized"}}, op)


def assert_fixed(warning, resource, status):
    assert warning.startswith(f"aws:{resource}:{status}:"), warning
    assert "Assessment incomplete" in warning
    assert "123456789012" not in warning and "private-marker" not in warning and "arn:" not in warning


def test_throttle_codes_cover_pinned_botocore():
    standard = pytest.importorskip("botocore.retries.standard")
    assert set(standard.ThrottledRetryableChecker._THROTTLED_ERROR_CODES) <= AWS_THROTTLED_CODES


@pytest.mark.parametrize(
    "exc,status",
    [
        (client_error("AccessDeniedException"), CollectionStatus.DENIED),
        (client_error("UnrecognizedClientException"), CollectionStatus.DENIED),
        (client_error("ThrottlingException"), CollectionStatus.THROTTLED),
        (client_error("TooManyRequestsException"), CollectionStatus.THROTTLED),
        (client_error("InternalServerException"), CollectionStatus.UNAVAILABLE),
        (botocore_exceptions.NoCredentialsError(), CollectionStatus.DENIED),
        (botocore_exceptions.EndpointConnectionError(endpoint_url="https://x.invalid"), CollectionStatus.UNAVAILABLE),
        (RuntimeError(PRIVATE), CollectionStatus.UNAVAILABLE),
    ],
)
def test_classification(exc, status):
    assert aws_read_status(exc) == status
    assert_fixed(aws_read_warning("svc", exc), "svc", status.value)


class _Pages:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        if isinstance(self.pages, Exception):
            raise self.pages
        return self.pages


def test_action_group_detail_failure_is_classified_and_others_kept():
    client = MagicMock()
    groups = [{"actionGroupName": "ag1", "actionGroupId": "1"}, {"actionGroupName": "ag2", "actionGroupId": "2"}]
    client.get_paginator.return_value = _Pages([{"actionGroupSummaries": groups}])

    def detail(**kwargs):
        if kwargs["actionGroupId"] == "1":
            raise client_error("AccessDeniedException", "GetAgentActionGroup")
        return {"agentActionGroup": {"actionGroupExecutor": {}}}

    client.get_agent_action_group.side_effect = detail
    warnings: list[str] = []
    servers = aws._get_action_group_servers(client, None, "AGENT1", "us-east-1", warnings)
    assert [s.name for s in servers] == ["action-group:ag2"]
    assert len(warnings) == 1
    assert_fixed(warnings[0], "bedrock-action-groups", "denied")


def test_action_group_listing_failure_is_classified():
    client = MagicMock()
    client.get_paginator.return_value = _Pages(client_error("ThrottlingException"))
    warnings: list[str] = []
    assert aws._get_action_group_servers(client, None, "AGENT1", "us-east-1", warnings) == []
    assert len(warnings) == 1
    assert_fixed(warnings[0], "bedrock-action-groups", "throttled")


def test_bedrock_agent_detail_failure_is_classified():
    client = MagicMock()
    client.get_paginator.return_value = _Pages([{"agentSummaries": [{"agentId": "A1", "agentName": "n"}]}])
    client.get_agent.side_effect = client_error("AccessDeniedException")
    session = MagicMock()
    session.client.return_value = client
    agents, warnings = aws._discover_bedrock(session, "us-east-1")
    assert agents == []
    assert_fixed(warnings[0], "bedrock-agents", "denied")


def test_step_function_describe_failure_is_classified():
    client = MagicMock()
    client.get_paginator.return_value = _Pages([{"stateMachines": [{"stateMachineArn": PRIVATE, "name": "sm"}]}])
    client.describe_state_machine.side_effect = client_error("ThrottlingException")
    session = MagicMock()
    session.client.return_value = client
    agents, warnings = aws._discover_step_functions(session, "us-east-1", [])
    assert agents == []
    assert_fixed(warnings[0], "step-functions", "throttled")


def test_job_level_client_error_has_no_provider_text():
    def job():
        raise client_error("InternalServerException")

    agents: list = []
    warnings: list[str] = []
    assert aws._collect_aws_discovery_jobs(
        [("ecs", job)], agents, warnings, [], client_error=ClientError, no_credentials_error=botocore_exceptions.NoCredentialsError
    )
    assert_fixed(warnings[0], "ecs", "unavailable")


def test_job_level_access_denied_keeps_permission_guidance():
    def job():
        raise client_error("AccessDeniedException")

    warnings: list[str] = []
    aws._collect_aws_discovery_jobs(
        [("ecs", job)], [], warnings, [], client_error=ClientError, no_credentials_error=botocore_exceptions.NoCredentialsError
    )
    assert_fixed(warnings[0], "ecs", "denied")
    assert "AmazonECSReadOnlyAccess" in warnings[0]


def _session(client):
    session = MagicMock()
    session.client.return_value = client
    return session


def test_ecs_failures_are_classified():
    client = MagicMock()
    client.get_paginator.return_value = _Pages(client_error("AccessDeniedException"))
    refs, warnings = aws_compute._discover_ecs_images(_session(client), "us-east-1")
    assert refs == []
    assert_fixed(warnings[0], "ecs-clusters", "denied")


def test_sagemaker_failures_are_classified():
    client = MagicMock()
    client.get_paginator.return_value = _Pages([{"Endpoints": [{"EndpointName": "e1"}]}])
    client.describe_endpoint.side_effect = client_error("ThrottlingException")
    agents, warnings = aws_compute._discover_sagemaker(_session(client), "us-east-1")
    assert agents == []
    assert_fixed(warnings[0], "sagemaker-endpoints", "throttled")


def test_ec2_bad_instance_does_not_drop_neighbors(monkeypatch):
    instances = [{"InstanceId": "i-1"}, {"InstanceId": "i-bad"}, {"InstanceId": "i-3"}]
    client = MagicMock()
    client.get_paginator.return_value = _Pages([{"Reservations": [{"Instances": instances}]}])
    real = aws_compute._ec2_instance_agent

    def convert(instance, region, account_id):
        if instance["InstanceId"] == "i-bad":
            raise KeyError(PRIVATE)
        return real(instance, region, account_id)

    monkeypatch.setattr(aws_compute, "_ec2_instance_agent", convert)
    agents, warnings = aws_compute._discover_ec2_instances(_session(client), "us-east-1", tag_filter={"team": "ml"})
    assert len(agents) == 2
    assert len(warnings) == 1
    assert_fixed(warnings[0], "ec2-instances", "unavailable")
