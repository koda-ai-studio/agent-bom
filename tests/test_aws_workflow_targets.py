"""Workflow configuration cannot establish an invocation or resolve expressions."""

from agent_bom.cloud.aws import _extract_sfn_task_resources


def test_dynamic_function_expressions_are_not_exact_targets():
    definition = {
        "States": {
            "Invoke": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName.$": "arn:aws:lambda:us-east-1:111111111111:function:expression"},
            }
        }
    }
    assert _extract_sfn_task_resources(definition) == []


def test_optimized_lambda_target_preserves_version_and_does_not_inventory_service_pseudo_arn():
    arn = "arn:aws:lambda:us-east-1:111111111111:function:invoice:3"
    definition = {
        "States": {
            "Map": {
                "Type": "Map",
                "ItemProcessor": {
                    "States": {
                        "Invoke": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "Parameters": {"FunctionName": arn}}
                    }
                },
            }
        }
    }
    assert _extract_sfn_task_resources(definition) == [arn]


def test_lambda_inventory_preserves_version_without_claiming_mcp(monkeypatch):
    from unittest.mock import MagicMock

    from agent_bom.cloud import aws
    from agent_bom.models import TransportType

    session = MagicMock()
    session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {
            "Functions": [
                {
                    "FunctionName": "invoice",
                    "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:invoice",
                    "Runtime": "python3.12",
                    "Version": "3",
                    "Role": "arn:aws:iam::111111111111:role/invoice",
                }
            ]
        }
    ]
    monkeypatch.setattr(aws, "_extract_lambda_packages", lambda *args: [])
    agents, _ = aws._discover_lambda_functions(session, "us-east-1", [], account_id="111111111111")
    assert agents[0].metadata["cloud_origin"]["raw_identity"]["function_version"] == "3"
    assert not agents[0].mcp_servers[0].is_mcp_surface
    assert agents[0].mcp_servers[0].transport == TransportType.UNKNOWN


def test_workflow_qualified_lambda_has_readable_name_and_configuration_basis(monkeypatch):
    import json
    from unittest.mock import MagicMock

    from agent_bom.cloud import aws

    arn = "arn:aws:lambda:us-east-1:111111111111:function:invoice:live"
    session = MagicMock()
    client = session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [{"stateMachines": [{"name": "billing", "stateMachineArn": "workflow"}]}]
    client.describe_state_machine.return_value = {
        "definition": json.dumps(
            {
                "States": {
                    "Invoke": {
                        "Type": "Task",
                        "Resource": arn,
                    }
                }
            }
        )
    }
    monkeypatch.setattr(aws, "_extract_lambda_packages", lambda *args: [])
    agents, _ = aws._discover_step_functions(session, "us-east-1", [], account_id="111111111111")
    server = agents[0].mcp_servers[0]
    assert server.name == "sfn-lambda:invoice:live"
    assert server.args == [arn]
    assert not server.is_mcp_surface
    assert server.connection_metadata["relationship_basis"] == "configured_workflow_target"
    assert server.connection_metadata["execution_proven"] is False
