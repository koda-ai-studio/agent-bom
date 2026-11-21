"""Three-cloud runtime credential, role and storage accuracy regressions."""

from dataclasses import asdict
from pathlib import Path

import pytest

from agent_bom.iac.terraform_security import scan_terraform_security


def scan(tmp_path, text, rule):
    path = tmp_path / "main.tf"
    path.write_text(text)
    return [f for f in scan_terraform_security(path) if f.rule_id == rule]


def resource(kind, body):
    return f'resource "{kind}" "test" {{\n{body}\n}}\n'


@pytest.mark.parametrize("kind", ["aws_ecs_task_definition", "azurerm_container_app", "google_cloud_run_v2_service"])
@pytest.mark.parametrize("name", ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"])
def test_plain_model_key_even_placeholder(tmp_path, kind, name):
    body = f'env {{\n name = "{name}"\n value = "private-placeholder"\n}}'
    if kind == "aws_ecs_task_definition":
        body = f'container_definitions = jsonencode([{{ environment = [{{ name = "{name}", value = "private-placeholder" }}] }}])'
    found = scan(tmp_path, resource(kind, body), "TF-SEC-052")
    assert len(found) == 1
    assert found[0].severity == "high"
    assert "private-placeholder" not in str(asdict(found[0]))


@pytest.mark.parametrize(
    "kind,body",
    [
        ("azurerm_container_app", 'env {\n name = "OPENAI_API_KEY"\n secret_name = "model-key"\n}'),
        (
            "google_cloud_run_v2_service",
            'env {\n name = "OPENAI_API_KEY"\n value_source {\n secret_key_ref {\n secret = "model-key"\n version = "latest"\n}\n}\n}',
        ),
        (
            "aws_ecs_task_definition",
            'container_definitions = jsonencode([{ secrets = [{ name = "OPENAI_API_KEY", valueFrom = "secret-reference" }] }])',
        ),
        ("azurerm_container_app", 'env {\n name = "OPENAI_MODEL"\n value = "model-name"\n}'),
    ],
)
def test_secret_refs_and_noncredentials_are_not_plain_keys(tmp_path, kind, body):
    assert scan(tmp_path, resource(kind, body), "TF-SEC-052") == []


@pytest.mark.parametrize("kind", ["google_project_iam_member", "google_project_iam_binding"])
@pytest.mark.parametrize(
    "role,expected",
    [("roles/storage.admin", 1), ("roles/editor", 1), ("roles/owner", 1), ("roles/storage.objectViewer", 0), ("var.role", 0)],
)
def test_project_roles(tmp_path, kind, role, expected):
    value = role if role == "var.role" else f'"{role}"'
    assert len(scan(tmp_path, resource(kind, f"role = {value}"), "TF-SEC-212")) == expected


@pytest.mark.parametrize(
    "scope,broad",
    [
        ("azurerm_resource_group.lab.id", True),
        ("data.azurerm_subscription.current.id", True),
        ('"/subscriptions/fixture/resourceGroups/lab"', True),
        ('"/subscriptions/fixture"', True),
        ("azurerm_storage_account.lab.id", False),
        ("var.scope", False),
        ('"/subscriptions/fixture/resourceGroups/lab/providers/Microsoft.Storage/storageAccounts/a"', False),
    ],
)
@pytest.mark.parametrize("role", ["Owner", "Contributor", "Reader"])
def test_azure_roles_are_scope_aware(tmp_path, scope, broad, role):
    body = f'scope = {scope}\nrole_definition_name = "{role}"'
    assert len(scan(tmp_path, resource("azurerm_role_assignment", body), "TF-SEC-113")) == int(broad and role != "Reader")


def test_s3_implicit_encryption_is_not_a_vulnerability(tmp_path):
    assert scan(tmp_path, resource("aws_s3_bucket", 'bucket = "fixture"'), "TF-SEC-001") == []


def test_s3_explicit_encryption_also_stays_quiet(tmp_path):
    assert scan(tmp_path, resource("aws_s3_bucket", "server_side_encryption_configuration {}"), "TF-SEC-001") == []


@pytest.mark.parametrize("linked,expected", [(True, 1), (False, 2)])
def test_public_blob_chain_only_deduplicates_linked_account(tmp_path, linked, expected):
    account = resource("azurerm_storage_account", "allow_nested_items_to_be_public = true")
    parent = "test" if linked else "other"
    container = resource(
        "azurerm_storage_container", f'storage_account_id = azurerm_storage_account.{parent}.id\ncontainer_access_type = "blob"'
    )
    findings = scan(tmp_path, account + container, "TF-SEC-101")
    assert len(findings) == expected
    assert any("container_access_type" in f.message for f in findings)


def test_private_container_does_not_hide_account_setting(tmp_path):
    text = resource("azurerm_storage_account", "allow_nested_items_to_be_public = true") + resource(
        "azurerm_storage_container", 'storage_account_id = azurerm_storage_account.test.id\ncontainer_access_type = "private"'
    )
    assert len(scan(tmp_path, text, "TF-SEC-101")) == 1


def test_accuracy_fixture(tmp_path):
    fixture = Path(__file__).parent / "fixtures/iac_accuracy/terraform/three_cloud.tf"
    findings = scan_terraform_security(fixture)
    for rule, count in [("TF-SEC-052", 3), ("TF-SEC-113", 1), ("TF-SEC-212", 1), ("TF-SEC-101", 1), ("TF-SEC-001", 0)]:
        assert len([f for f in findings if f.rule_id == rule]) == count


@pytest.mark.parametrize("assignment", ["value = var.model_key", 'value = "${var.model_key}"', '"value": "placeholder"'])
def test_ecs_plain_channel_is_unsafe_even_with_variable_input(tmp_path, assignment):
    body = 'container_definitions = jsonencode([{ environment = [{ "name": "COHERE_API_KEY", ' + assignment + " }] }])"
    assert len(scan(tmp_path, resource("aws_ecs_task_definition", body), "TF-SEC-052")) == 1


def test_commented_keys_and_roles_are_not_findings(tmp_path):
    text = resource("azurerm_container_app", '# env { name = "OPENAI_API_KEY", value = "placeholder" }')
    assert scan(tmp_path, text, "TF-SEC-052") == []
    text = resource("google_project_iam_member", '# role = "roles/owner"\nrole = "roles/viewer"')
    assert scan(tmp_path, text, "TF-SEC-212") == []


def test_distinct_public_containers_are_not_collapsed(tmp_path):
    text = resource("azurerm_storage_account", "allow_nested_items_to_be_public = true")
    for name in ["one", "two"]:
        text += (
            f'resource "azurerm_storage_container" "{name}" {{\n'
            ' storage_account_id = azurerm_storage_account.test.id\n container_access_type = "blob"\n}\n'
        )
    assert len(scan(tmp_path, text, "TF-SEC-101")) == 2


def test_ecs_json_string_definition_is_scanned_without_value_leak(tmp_path):
    import json

    definition = json.dumps([{"environment": [{"name": "OPENAI_API_KEY", "value": "private-placeholder"}]}])
    findings = scan(tmp_path, resource("aws_ecs_task_definition", "container_definitions = " + json.dumps(definition)), "TF-SEC-052")
    assert len(findings) == 1
    assert findings[0].line_number == 2
    assert "private-placeholder" not in str(asdict(findings[0]))
