"""The demo estate's CIS control catalog: what fails, and what was recorded passing.

Both halves copy the shipped benchmark scanners (``agent_bom.cloud.*_cis``) —
same check ids, titles, severities and sections — so the demo speaks the
product's real control vocabulary. ``tests/test_demo_estate_findings.py`` pins
every entry to the scanner source.

``_CATALOG`` holds the controls that fail on a share of the resources they
apply to; :mod:`enterprise_findings` turns those into findings and the graph
projects them. ``_PASSING`` holds controls the estate evaluated with no
failure. A pass is a recorded result over the estate's own inventory: a control
with nothing in the estate to evaluate it against records nothing, and so stays
not evaluated rather than reading as a pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_bom.demo_estate.enterprise import EnterpriseEstate


@dataclass(frozen=True, slots=True)
class EstateCheck:
    """One posture control, scoped to the resource types it can fail on.

    ``check_id``, ``title``, ``severity`` and ``recommendation`` are copied from
    the shipped benchmark scanner for this cloud — the demo must not invent
    control identity. ``setting``/``observed``/``expected`` are the
    configuration edge: what was read, and what it should have been.
    """

    provider: str
    check_id: str
    title: str
    severity: str
    cis_section: str
    recommendation: str
    resource_types: tuple[str, ...]
    setting: str
    observed: str
    expected: str
    # Percent of matching assets that fail this control. Chosen per control so
    # the estate reads like an estate: a few systemic failures, most controls
    # failing on a minority of resources, no band dominating.
    prevalence: int


_AWS_IAM = "1 - Identity and Access Management"
_AWS_STORAGE = "2 - Storage"
_AWS_NETWORK = "5 - Networking"
_AZ_STORAGE = "3 - Storage Accounts"
_AZ_DATABASE = "4 - Database Services"
_AZ_VM = "7 - Virtual Machines"
_AZ_KEYVAULT = "8 - Key Vault"
_AZ_APPSERVICE = "9 - App Service"
_GCP_IAM = "1 - Identity and Access Management"
_GCP_COMPUTE = "4 - Virtual Machines"
_GCP_STORAGE = "5 - Cloud Storage"
_GCP_SQL = "6 - Cloud SQL"
_SF_AUTH = "1 - Account and Authentication"
_SF_DATA = "3 - Data Protection"
_SF_ACCESS = "5 - Access Control"


_CATALOG: tuple[EstateCheck, ...] = (
    # ── AWS ──────────────────────────────────────────────────────────────
    EstateCheck(
        provider="aws",
        check_id="1.16",
        title="No full-admin IAM policies attached",
        severity="critical",
        cis_section=_AWS_IAM,
        recommendation="Remove or scope down policies that grant '*' on '*' resources.",
        resource_types=("iam_role",),
        setting="attached_policy_actions",
        observed="Action '*' on Resource '*'",
        expected="Least-privilege actions scoped to named resources",
        prevalence=9,
    ),
    EstateCheck(
        provider="aws",
        check_id="1.15",
        title="IAM permissions granted via groups or roles only",
        severity="medium",
        cis_section=_AWS_IAM,
        recommendation="Remove inline and directly attached policies from IAM users; use groups instead.",
        resource_types=("iam_role",),
        setting="inline_policy_count",
        observed="2 inline policies attached directly",
        expected="0 inline policies; permissions granted through groups or roles",
        prevalence=21,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.1.2",
        title="S3 bucket server-side encryption enabled",
        severity="medium",
        cis_section=_AWS_STORAGE,
        recommendation="Enable default encryption (SSE-S3 or SSE-KMS) on all S3 buckets.",
        resource_types=("bucket",),
        setting="ServerSideEncryptionConfiguration",
        observed="absent",
        expected="ApplyServerSideEncryptionByDefault=aws:kms",
        prevalence=24,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.1.1",
        title="S3 account-level public access block configured",
        severity="high",
        cis_section=_AWS_STORAGE,
        recommendation="Enable all four S3 public access block settings at the account level.",
        resource_types=("bucket",),
        setting="PublicAccessBlockConfiguration.BlockPublicPolicy",
        observed="false",
        expected="true",
        prevalence=11,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.1.4",
        title="S3 bucket versioning enabled",
        severity="medium",
        cis_section=_AWS_STORAGE,
        recommendation="Enable versioning on all S3 buckets for data protection.",
        resource_types=("bucket",),
        setting="VersioningConfiguration.Status",
        observed="Suspended",
        expected="Enabled",
        prevalence=18,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.3.1",
        title="RDS encryption at rest enabled",
        severity="high",
        cis_section=_AWS_STORAGE,
        recommendation="Enable encryption at rest when creating RDS instances (cannot be changed post-creation).",
        resource_types=("database",),
        setting="StorageEncrypted",
        observed="false",
        expected="true",
        prevalence=14,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.3.2",
        title="RDS auto minor version upgrade enabled",
        severity="medium",
        cis_section=_AWS_STORAGE,
        recommendation="Enable auto minor version upgrade on all RDS instances.",
        resource_types=("database",),
        setting="AutoMinorVersionUpgrade",
        observed="false",
        expected="true",
        prevalence=27,
    ),
    EstateCheck(
        provider="aws",
        check_id="5.2",
        title="No unrestricted ingress to admin ports (22, 3389)",
        severity="high",
        cis_section=_AWS_NETWORK,
        recommendation="Restrict SSH (22) and RDP (3389) to specific IP ranges.",
        resource_types=("instance", "cluster"),
        setting="security_group_ingress",
        observed="0.0.0.0/0 -> tcp/22",
        expected="Ingress restricted to approved CIDR ranges",
        prevalence=13,
    ),
    EstateCheck(
        provider="aws",
        check_id="5.3",
        title="Default security group restricts all traffic",
        severity="medium",
        cis_section=_AWS_NETWORK,
        recommendation="Remove all inbound and outbound rules from default security groups.",
        resource_types=("instance", "function"),
        setting="default_security_group_rules",
        observed="1 inbound rule, 1 outbound rule",
        expected="0 inbound rules, 0 outbound rules",
        prevalence=16,
    ),
    # ── Azure ────────────────────────────────────────────────────────────
    EstateCheck(
        provider="azure",
        check_id="3.1",
        title="Secure transfer required on storage accounts",
        severity="high",
        cis_section=_AZ_STORAGE,
        recommendation="Enable 'Secure transfer required' on all storage accounts to enforce HTTPS-only access.",
        resource_types=("storage_account",),
        setting="supportsHttpsTrafficOnly",
        observed="false",
        expected="true",
        prevalence=12,
    ),
    EstateCheck(
        provider="azure",
        check_id="3.7",
        title="Blob containers set to private access",
        severity="high",
        cis_section=_AZ_STORAGE,
        recommendation="Disable public blob access at the storage account level and audit all containers.",
        resource_types=("storage_account",),
        setting="allowBlobPublicAccess",
        observed="true",
        expected="false",
        prevalence=9,
    ),
    EstateCheck(
        provider="azure",
        check_id="3.11",
        title="Private endpoints used for storage accounts",
        severity="high",
        cis_section=_AZ_STORAGE,
        recommendation="Configure private endpoints for all storage accounts to restrict network access.",
        resource_types=("storage_account",),
        setting="privateEndpointConnections",
        observed="0 connections; publicNetworkAccess=Enabled",
        expected="At least one approved private endpoint; public network access disabled",
        prevalence=26,
    ),
    EstateCheck(
        provider="azure",
        check_id="4.1.2",
        title="Transparent Data Encryption enabled on SQL servers",
        severity="high",
        cis_section=_AZ_DATABASE,
        recommendation="Enable Transparent Data Encryption on all SQL databases.",
        resource_types=("sql_database",),
        setting="transparentDataEncryption.state",
        observed="Disabled",
        expected="Enabled",
        prevalence=15,
    ),
    EstateCheck(
        provider="azure",
        check_id="4.2.1",
        title="TLS 1.2 or higher on database servers",
        severity="high",
        cis_section=_AZ_DATABASE,
        recommendation="Set the minimum TLS version to TLS 1.2 on all Azure SQL, MySQL, and PostgreSQL servers.",
        resource_types=("sql_database",),
        setting="minimalTlsVersion",
        observed="1.0",
        expected="1.2",
        prevalence=19,
    ),
    EstateCheck(
        provider="azure",
        check_id="7.1",
        title="Virtual machines use Managed Disks",
        severity="medium",
        cis_section=_AZ_VM,
        recommendation="Migrate all VM disks to Managed Disks for improved reliability and security.",
        resource_types=("virtual_machine",),
        setting="storageProfile.osDisk.managedDisk",
        observed="absent (unmanaged VHD in a storage account)",
        expected="Managed disk reference",
        prevalence=17,
    ),
    EstateCheck(
        provider="azure",
        check_id="8.1",
        title="Expiration date set on Key Vault keys",
        severity="medium",
        cis_section=_AZ_KEYVAULT,
        recommendation="Set an expiration date on all Key Vault keys to enforce key rotation.",
        resource_types=("key_vault",),
        setting="key.attributes.exp",
        observed="null",
        expected="A rotation date within policy",
        prevalence=100,
    ),
    EstateCheck(
        provider="azure",
        check_id="8.6",
        title="Key Vault secrets have a content type set",
        severity="low",
        cis_section=_AZ_KEYVAULT,
        recommendation="Set a content type on all Key Vault secrets so consumers can validate what they retrieve.",
        resource_types=("key_vault",),
        setting="secret.contentType",
        observed="null on 3 of 5 secrets",
        expected="A content type on every secret",
        prevalence=100,
    ),
    EstateCheck(
        provider="azure",
        check_id="9.1",
        title="App Service Authentication configured",
        severity="high",
        cis_section=_AZ_APPSERVICE,
        recommendation="Enable App Service Authentication (EasyAuth) on all web apps.",
        resource_types=("function_app",),
        setting="siteAuthSettings.enabled",
        observed="false",
        expected="true",
        prevalence=22,
    ),
    # ── GCP ──────────────────────────────────────────────────────────────
    EstateCheck(
        provider="gcp",
        check_id="1.4",
        title="No user-managed service account keys",
        severity="medium",
        cis_section=_GCP_IAM,
        recommendation="Delete user-managed service account keys and use short-lived credentials via Workload Identity.",
        resource_types=("service_account",),
        setting="user_managed_keys",
        observed="1 user-managed key, created 412 days ago",
        expected="0 user-managed keys; short-lived credentials only",
        prevalence=23,
    ),
    EstateCheck(
        provider="gcp",
        check_id="3.6",
        title="SSH (port 22) restricted from the internet",
        severity="critical",
        cis_section="3 - Networking",
        recommendation="Remove or restrict firewall rules that allow TCP port 22 from 0.0.0.0/0 or ::/0.",
        resource_types=("instance",),
        setting="firewall_rule.sourceRanges",
        observed="0.0.0.0/0 -> tcp/22",
        expected="Approved CIDR ranges only",
        prevalence=7,
    ),
    EstateCheck(
        provider="gcp",
        check_id="4.1",
        title="Instances not using default service account",
        severity="high",
        cis_section=_GCP_COMPUTE,
        recommendation="Create and assign a custom service account to each VM instance instead of using the default.",
        resource_types=("instance",),
        setting="serviceAccounts[0].email",
        observed="compute default service account",
        expected="A dedicated least-privilege service account",
        prevalence=20,
    ),
    EstateCheck(
        provider="gcp",
        check_id="5.1",
        title="Cloud Storage buckets not publicly accessible",
        severity="high",
        cis_section=_GCP_STORAGE,
        recommendation="Remove allUsers and allAuthenticatedUsers from bucket IAM policies.",
        resource_types=("bucket",),
        setting="iamPolicy.bindings",
        observed="allUsers has roles/storage.objectViewer",
        expected="No allUsers or allAuthenticatedUsers principals",
        prevalence=8,
    ),
    EstateCheck(
        provider="gcp",
        check_id="5.2",
        title="Uniform bucket-level access enabled on buckets",
        severity="medium",
        cis_section=_GCP_STORAGE,
        recommendation="Enable uniform bucket-level access on all Cloud Storage buckets to use IAM exclusively.",
        resource_types=("bucket",),
        setting="iamConfiguration.uniformBucketLevelAccess.enabled",
        observed="false",
        expected="true",
        prevalence=29,
    ),
    EstateCheck(
        provider="gcp",
        check_id="6.2",
        title="Cloud SQL instances lack public IPs",
        severity="high",
        cis_section=_GCP_SQL,
        recommendation="Remove public IP addresses from Cloud SQL instances and use private IP or Cloud SQL Proxy.",
        resource_types=("database",),
        setting="settings.ipConfiguration.ipv4Enabled",
        observed="true",
        expected="false",
        prevalence=16,
    ),
    # ── Snowflake ────────────────────────────────────────────────────────
    EstateCheck(
        provider="snowflake",
        check_id="1.4",
        title="ACCOUNTADMIN granted to at most 2 users",
        severity="critical",
        cis_section=_SF_AUTH,
        recommendation="Limit ACCOUNTADMIN grants to a maximum of 2 users.",
        resource_types=("role",),
        setting="accountadmin_grantees",
        observed="6 users hold ACCOUNTADMIN",
        expected="At most 2 users",
        prevalence=10,
    ),
    EstateCheck(
        provider="snowflake",
        check_id="5.1",
        title="PUBLIC role has no direct privilege grants",
        severity="high",
        cis_section=_SF_ACCESS,
        recommendation="Revoke all grants from the PUBLIC role: REVOKE ALL ON <object> FROM ROLE PUBLIC;",
        resource_types=("role", "warehouse"),
        setting="grants_to_public_role",
        observed="SELECT granted to PUBLIC",
        expected="No privileges granted to PUBLIC",
        prevalence=18,
    ),
    EstateCheck(
        provider="snowflake",
        check_id="3.1",
        title="Tri-Secret Secure (customer-managed key) enabled",
        severity="high",
        cis_section=_SF_DATA,
        recommendation="Contact Snowflake support to enable Tri-Secret Secure with your cloud KMS.",
        resource_types=("database", "table"),
        setting="tri_secret_secure",
        observed="disabled",
        expected="enabled with a customer-managed key",
        prevalence=12,
    ),
    EstateCheck(
        provider="snowflake",
        check_id="3.2",
        title="Data sharing restricted to authorized accounts",
        severity="medium",
        cis_section=_SF_DATA,
        recommendation="Review outbound shares and remove unauthorized consumers.",
        resource_types=("share", "stage"),
        setting="share_consumers",
        observed="1 consumer outside the approved account list",
        expected="Only approved consumer accounts",
        prevalence=25,
    ),
)


def _catalog_index() -> dict[tuple[str, str], tuple[EstateCheck, ...]]:
    index: dict[tuple[str, str], list[EstateCheck]] = {}
    for check in _CATALOG:
        for resource_type in check.resource_types:
            index.setdefault((check.provider, resource_type), []).append(check)
    return {key: tuple(value) for key, value in index.items()}


_CATALOG_BY_TARGET = _catalog_index()

# An account-level control is evaluated once per inventoried account.
_ACCOUNT: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EstatePass:
    """A control evaluated across the estate with no failing resource."""

    provider: str
    check_id: str
    title: str
    severity: str
    cis_section: str
    # Resource types it is evaluated on; empty means once per account.
    resource_types: tuple[str, ...]


_PASSING: tuple[EstatePass, ...] = (
    # ── AWS ──
    EstatePass("aws", "1.4", "No root account access keys", "critical", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.5", "Root account MFA enabled", "critical", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.6", "Hardware MFA for root account", "critical", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.7", "Root user not used for daily tasks", "high", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.8", "IAM password policy minimum length >= 14", "medium", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.9", "IAM password policy blocks password reuse", "medium", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.10", "MFA on all console-access IAM users", "high", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.13", "At most one active access key per IAM user", "medium", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.17", "Support role exists for AWS Support incidents", "medium", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "1.19", "Instance roles used for resource access", "medium", "1 - Identity and Access Management", ("instance",)),
    EstatePass("aws", "1.20", "IAM Access Analyzer enabled in all regions", "medium", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("aws", "2.2.1", "EBS default volume encryption enabled", "medium", "2 - Storage", _ACCOUNT),
    EstatePass("aws", "2.4.1", "Customer-managed KMS key rotation enabled", "medium", "2 - Storage", _ACCOUNT),
    EstatePass("aws", "3.1", "CloudTrail enabled in all regions", "high", "3 - Logging", _ACCOUNT),
    EstatePass("aws", "3.2", "CloudTrail log file validation enabled", "medium", "3 - Logging", _ACCOUNT),
    EstatePass("aws", "3.3", "CloudTrail S3 bucket not publicly accessible", "critical", "3 - Logging", _ACCOUNT),
    EstatePass("aws", "3.5", "CloudTrail records management events in all regions", "medium", "3 - Logging", _ACCOUNT),
    EstatePass("aws", "3.7", "CloudTrail logs encrypted with KMS CMK", "medium", "3 - Logging", _ACCOUNT),
    EstatePass("aws", "3.9", "VPC flow logging enabled in all VPCs", "medium", "3 - Logging", _ACCOUNT),
    EstatePass("aws", "4.16", "AWS Security Hub enabled", "medium", "4 - Monitoring", _ACCOUNT),
    EstatePass("aws", "5.1", "No NACL allows unrestricted ingress to admin ports", "high", "5 - Networking", _ACCOUNT),
    EstatePass("aws", "5.5", "No security group allows all-ports ingress from any IP", "high", "5 - Networking", ("instance",)),
    # ── Azure ──
    EstatePass(
        "azure", "1.1", "No subscription Owner role for guest/external users", "high", "1 - Identity and Access Management", _ACCOUNT
    ),
    EstatePass(
        "azure", "1.2", "No subscription Contributor role for guest users", "medium", "1 - Identity and Access Management", _ACCOUNT
    ),
    EstatePass("azure", "1.5", "No custom subscription Administrator roles", "high", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("azure", "1.6", "MFA enabled for all users", "critical", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("azure", "1.8", "MFA enabled for Azure Portal access", "critical", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("azure", "2.1", "Microsoft Defender for Servers enabled", "high", "2 - Microsoft Defender for Cloud", _ACCOUNT),
    EstatePass("azure", "2.4", "Microsoft Defender for Storage enabled", "high", "2 - Microsoft Defender for Cloud", _ACCOUNT),
    EstatePass("azure", "2.5", "Microsoft Defender for Key Vault enabled", "high", "2 - Microsoft Defender for Cloud", _ACCOUNT),
    EstatePass("azure", "3.10", "Soft delete enabled for Azure Storage", "medium", "3 - Storage Accounts", ("storage_account",)),
    EstatePass(
        "azure", "3.12", "Infrastructure encryption enabled on storage accounts", "medium", "3 - Storage Accounts", ("storage_account",)
    ),
    EstatePass("azure", "4.1.1", "Auditing enabled on SQL servers", "high", "4 - Database Services", ("sql_database",)),
    EstatePass("azure", "4.1.3", "Azure AD admin configured for SQL servers", "high", "4 - Database Services", ("sql_database",)),
    EstatePass("azure", "4.1.6", "Public network access disabled on SQL servers", "high", "4 - Database Services", ("sql_database",)),
    EstatePass("azure", "5.1.1", "Diagnostic setting captures Activity Log", "medium", "5 - Logging and Monitoring", _ACCOUNT),
    EstatePass("azure", "5.1.2", "Activity Log retention 365 days or greater", "medium", "5 - Logging and Monitoring", _ACCOUNT),
    EstatePass("azure", "6.1", "RDP access from internet restricted", "critical", "6 - Networking", ("virtual_machine",)),
    EstatePass("azure", "6.2", "SSH access from internet restricted", "critical", "6 - Networking", ("virtual_machine",)),
    EstatePass("azure", "7.2", "VM OS disks use Managed Disks", "medium", "7 - Virtual Machines", ("virtual_machine",)),
    EstatePass("azure", "7.6", "Endpoint protection installed on VMs", "high", "7 - Virtual Machines", ("virtual_machine",)),
    EstatePass("azure", "8.3", "Key Vault recoverable (soft-delete and purge protection)", "high", "8 - Key Vault", ("key_vault",)),
    EstatePass("azure", "9.2", "Web app redirects HTTP to HTTPS", "high", "9 - App Service", ("function_app",)),
    EstatePass("azure", "9.3", "Web app uses latest TLS version", "high", "9 - App Service", ("function_app",)),
    EstatePass("azure", "9.6", "FTP access disabled for App Service", "high", "9 - App Service", ("function_app",)),
    # ── GCP ──
    EstatePass("gcp", "1.5", "No primitive roles (Owner/Editor) at project level", "high", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("gcp", "1.6", "Service accounts lack admin privileges", "high", "1 - Identity and Access Management", ("service_account",)),
    EstatePass("gcp", "1.9", "Cloud KMS keys not publicly accessible", "critical", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("gcp", "1.10", "KMS keys rotated within 90 days", "medium", "1 - Identity and Access Management", _ACCOUNT),
    EstatePass("gcp", "2.1", "Cloud Audit Logs configured for all services", "medium", "2 - Logging", _ACCOUNT),
    EstatePass("gcp", "2.2", "Log sink exports all log entries", "medium", "2 - Logging", _ACCOUNT),
    EstatePass("gcp", "3.1", "No default VPC network in the project", "medium", "3 - Networking", _ACCOUNT),
    EstatePass("gcp", "3.7", "RDP (port 3389) restricted from the internet", "critical", "3 - Networking", ("instance",)),
    EstatePass("gcp", "3.8", "ICMP firewall rules not open to the world", "medium", "3 - Networking", ("instance",)),
    EstatePass("gcp", "4.3", "Block Project-wide SSH Keys enabled on VMs", "medium", "4 - Virtual Machines", ("instance",)),
    EstatePass("gcp", "4.5", "Serial-port connection disabled on VMs", "medium", "4 - Virtual Machines", ("instance",)),
    EstatePass("gcp", "4.6", "IP forwarding disabled on instances", "medium", "4 - Virtual Machines", ("instance",)),
    EstatePass("gcp", "4.8", "Compute instances launched with Shielded VM", "medium", "4 - Virtual Machines", ("instance",)),
    EstatePass("gcp", "6.1", "Cloud SQL requires SSL for all connections", "high", "6 - Cloud SQL", ("database",)),
    EstatePass("gcp", "6.3", "Cloud SQL automated backups enabled", "high", "6 - Cloud SQL", ("database",)),
    # ── Snowflake ──
    EstatePass("snowflake", "1.1", "MFA enabled for password-auth users", "critical", "1 - Account and Authentication", _ACCOUNT),
    EstatePass("snowflake", "1.2", "Minimum password length 14 or greater", "medium", "1 - Account and Authentication", _ACCOUNT),
    EstatePass("snowflake", "1.3", "Session idle timeout 4 hours or less", "medium", "1 - Account and Authentication", _ACCOUNT),
    EstatePass("snowflake", "1.5", "Password history of 24 or greater", "medium", "1 - Account and Authentication", _ACCOUNT),
    EstatePass("snowflake", "1.6", "Password maximum age 90 days or less", "medium", "1 - Account and Authentication", _ACCOUNT),
    EstatePass("snowflake", "2.1", "Account-level network policies configured", "high", "2 - Network Security", _ACCOUNT),
    EstatePass("snowflake", "2.2", "Network policies disallow unrestricted access", "critical", "2 - Network Security", _ACCOUNT),
    EstatePass("snowflake", "4.1", "Access history enabled and collected", "high", "4 - Monitoring and Logging", _ACCOUNT),
    EstatePass("snowflake", "5.2", "No users default to ACCOUNTADMIN role", "high", "5 - Access Control", ("role",)),
)


def _evaluated_on(estate: EnterpriseEstate, check: EstatePass) -> tuple[int, str]:
    assets = [asset for asset in estate.assets if asset.provider == check.provider]
    if not check.resource_types:
        return len({asset.account_scope for asset in assets if asset.account_scope}), "account"
    return sum(1 for asset in assets if asset.resource_type in check.resource_types), "resource"


def estate_cis_passes(estate: EnterpriseEstate) -> list[tuple[str, dict[str, Any]]]:
    """Recorded passing results as ``(provider, check payload)``, only where the estate holds evidence."""
    passes: list[tuple[str, dict[str, Any]]] = []
    for check in _PASSING:
        evaluated, unit = _evaluated_on(estate, check)
        if not evaluated:
            continue
        payload = {
            "check_id": check.check_id,
            "title": check.title,
            "status": "pass",
            "severity": check.severity,
            "cis_section": check.cis_section,
            "evidence": f"Evaluated on {evaluated} {unit}(s); none failed.",
            "resource_ids": [],
            "evaluated_count": evaluated,
            "evaluated_unit": unit,
            "remediation": {},
        }
        passes.append((check.provider, payload))
    return passes


__all__ = ["EstateCheck", "EstatePass", "estate_cis_passes"]
