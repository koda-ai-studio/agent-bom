"""Provider descriptions and connection flags shared by the CLI front door."""

from dataclasses import dataclass


@dataclass(frozen=True)
class _ConnectSource:
    """Static description of one connectable cloud/source.

    All values are documentation pointers — ``connect`` never mutates anything
    and never calls a cloud API. ``cred_env_vars`` are the standard provider
    credential variables we look for to report whether a local scan will have
    something to read.
    """

    name: str
    title: str
    terraform_module: str
    provision_path: str
    cli_hint: str
    cloudshell_hint: str
    inventory_env: str
    inventory_value: str
    cred_env_vars: tuple[str, ...]
    scan_command: str
    role_summary: str
    audit_trail_note: str = ""


# Ordered to match the documented onboarding story (cloud → data platforms).
_CONNECT_SOURCES: dict[str, _ConnectSource] = {
    "aws": _ConnectSource(
        name="aws",
        title="Amazon Web Services",
        terraform_module="deploy/terraform/connect-aws",
        provision_path="scripts/provision/aws_readonly_policy.json",
        cli_hint="aws iam create-policy/role + SecurityAudit (see scripts/provision/README.md)",
        cloudshell_hint="Open AWS CloudShell → paste the CLI grant (no local Terraform required)",
        inventory_env="AGENT_BOM_AWS_INVENTORY",
        inventory_value="1",
        cred_env_vars=("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"),
        scan_command="agent-bom scan --aws",
        role_summary="IAM principal with AWS-managed SecurityAudit (+ ViewOnlyAccess). List/Describe/Get only.",
        audit_trail_note=(
            "Reuses this SAME SecurityAudit role — no new role. cloudtrail:LookupEvents is "
            "already granted by the AWS-managed SecurityAudit policy, so enabling it adds zero new permission."
        ),
    ),
    "azure": _ConnectSource(
        name="azure",
        title="Microsoft Azure",
        terraform_module="deploy/terraform/connect-azure",
        provision_path="scripts/provision/azure_readonly_role.json",
        cli_hint="az ad sp create-for-rbac --role Reader (see scripts/provision/README.md)",
        cloudshell_hint="Open Azure Cloud Shell → paste the az grant (no local Terraform required)",
        inventory_env="AGENT_BOM_AZURE_INVENTORY",
        inventory_value="1",
        cred_env_vars=("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"),
        scan_command="agent-bom scan --azure",
        role_summary="Service principal with the built-in Reader role. Read-only; no write/delete grants.",
        audit_trail_note=(
            "Reuses this SAME Reader/Security Reader role — no new role. The Activity Log read "
            "(Microsoft.Insights/eventtypes/values/read) sits inside the existing Reader grant in standard setups."
        ),
    ),
    "gcp": _ConnectSource(
        name="gcp",
        title="Google Cloud Platform",
        terraform_module="deploy/terraform/connect-gcp",
        provision_path="scripts/provision/gcp_readonly_role.yaml",
        cli_hint="gcloud iam service-accounts create + roles/viewer (see scripts/provision/README.md)",
        cloudshell_hint="Open Google Cloud Shell → paste the gcloud grant (no local Terraform required)",
        inventory_env="AGENT_BOM_GCP_INVENTORY",
        inventory_value="1",
        cred_env_vars=("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"),
        scan_command="agent-bom scan --gcp",
        role_summary="Service account with roles/viewer (+ roles/iam.securityReviewer). Read-only.",
        audit_trail_note=(
            "Reuses this SAME roles/viewer role — no new role. The audit-log read "
            "(logging.logEntries.list) sits inside the existing roles/viewer grant in standard setups."
        ),
    ),
    "databricks": _ConnectSource(
        name="databricks",
        title="Databricks",
        terraform_module="",
        provision_path="docs/cloud/DATABRICKS_CONNECTIONS.md",
        cli_hint="agent-bom connect databricks --host <workspace-url> --token-file <private-token-file>",
        cloudshell_hint="Workspace settings: provision a dedicated identity with scoped read permissions.",
        inventory_env="DATABRICKS_HOST",
        inventory_value="<workspace-url>",
        cred_env_vars=("DATABRICKS_HOST", "DATABRICKS_TOKEN"),
        scan_command="agent-bom scan --databricks",
        role_summary="Workspace inventory and vendor security best-practices reads; denied checks remain unevaluated.",
    ),
    "snowflake": _ConnectSource(
        name="snowflake",
        title="Snowflake",
        terraform_module="deploy/terraform/connect-snowflake",
        provision_path="scripts/provision/snowflake_readonly.sql",
        cli_hint="snow sql -f scripts/provision/snowflake_readonly.sql",
        cloudshell_hint="Snowsight SQL worksheet → paste snowflake_readonly.sql",
        inventory_env="SNOWFLAKE_ACCOUNT",
        inventory_value="<your-account-locator>",
        cred_env_vars=("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PRIVATE_KEY_PATH"),
        scan_command="agent-bom scan --snowflake",
        role_summary="Read-only role (warehouse USAGE + governance views). No DML/DDL grants.",
    ),
}


@dataclass(frozen=True)
class _ConnectField:
    """One provider flag and how it maps onto the canonical connection schema.

    ``kind`` selects the canonical target: ``role_ref`` and ``secret`` set the
    two required columns, ``secret_file`` reads the secret from a file path,
    ``regions`` is a repeatable list, and ``auth_param`` writes into the
    non-secret ``auth_params`` blob under ``auth_key``.
    """

    flag: str
    param: str
    kind: str
    help: str
    auth_key: str = ""


_CONNECT_FIELDS: dict[str, tuple[_ConnectField, ...]] = {
    "aws": (
        _ConnectField("--role-arn", "role_arn", "role_ref", "IAM role ARN to assume, read-only (the connection role_ref)."),
        _ConnectField("--external-id", "external_id", "secret", "STS ExternalId — write-only secret; never printed or logged."),
        _ConnectField("--region", "regions", "regions", "Region to scan (repeatable)."),
    ),
    "azure": (
        _ConnectField("--client-id", "client_id", "role_ref", "App/service-principal client id (the connection role_ref)."),
        _ConnectField("--client-secret", "client_secret", "secret", "Client secret — write-only; never printed or logged."),
        _ConnectField("--tenant-id", "tenant_id", "auth_param", "Azure AD tenant id.", auth_key="tenant_id"),
        _ConnectField("--subscription-id", "subscription_id", "auth_param", "Azure subscription id.", auth_key="subscription_id"),
    ),
    "gcp": (
        _ConnectField("--service-account", "service_account", "role_ref", "Service-account email (the connection role_ref)."),
        _ConnectField("--key-file", "key_file", "secret_file", "Path to the service-account key JSON — write-only; never printed."),
        _ConnectField("--project", "project", "auth_param", "GCP project id.", auth_key="project_id"),
    ),
    "databricks": (
        _ConnectField("--host", "host", "role_ref", "HTTPS Databricks workspace origin."),
        _ConnectField("--token-file", "token_file", "secret_file", "Private file containing the scoped workspace token; never printed."),
    ),
    "snowflake": (
        _ConnectField("--account", "account", "role_ref", "Snowflake account or account/user (the connection role_ref)."),
        _ConnectField("--private-key-file", "private_key_file", "secret_file", "Path to the PEM private key — write-only; never printed."),
        _ConnectField("--user", "user", "auth_param", "Snowflake user.", auth_key="user"),
        _ConnectField("--role", "role", "auth_param", "Snowflake role.", auth_key="role"),
        _ConnectField("--warehouse", "warehouse", "auth_param", "Snowflake warehouse.", auth_key="warehouse"),
    ),
}
