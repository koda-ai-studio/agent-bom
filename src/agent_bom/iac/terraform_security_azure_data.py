"""Azure database, Key Vault and disk rules (TF-SEC-105..108, 111, 112)."""

from __future__ import annotations

import re

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource, extract_block
from agent_bom.iac.terraform_security_hcl import attr, nested_block, tf_finding

AZURE_DB_SERVER_TYPES = frozenset(
    {
        "azurerm_mssql_server",
        "azurerm_postgresql_server",
        "azurerm_mysql_server",
        "azurerm_mariadb_server",
        "azurerm_postgresql_flexible_server",
        "azurerm_mysql_flexible_server",
    }
)
AZURE_SINGLE_SERVER_TYPES = frozenset({"azurerm_postgresql_server", "azurerm_mysql_server", "azurerm_mariadb_server"})
_PUBLIC_ACCESS_CIS = {"azurerm_mssql_server": "CIS-Azure-4.1.6"}
_SSL_ENFORCEMENT_CIS = {"azurerm_postgresql_server": "CIS-Azure-4.3.1", "azurerm_mysql_server": "CIS-Azure-4.2.2"}
_WEAK_DB_TLS = frozenset({"TLS1_0", "TLS1_1", "TLSEnforcementDisabled", "1.0", "1.1"})
_DISK_ENCRYPTION_ARGS = ("disk_encryption_set_id", "secure_vm_disk_encryption_set_id", "encryption_settings")
_AUDIT_POLICY_RE = re.compile(r'resource\s+"azurerm_mssql_server_extended_auditing_policy"\s+"[^"]+"\s*\{')
_SERVER_REF_RE = re.compile(r"\bserver_id\s*=\s*azurerm_mssql_server\.([A-Za-z0-9_-]+)\.id")


def tf_sec_105(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-105: database server reachable over public network access."""
    if attr(res.block, "delegated_subnet_id") is not None:
        return []
    found = attr(res.block, "public_network_access_enabled")
    if found is None:
        state, offset = "does not set public_network_access_enabled, which defaults to true", None
    elif found.boolean is True:
        state, offset = "sets public_network_access_enabled = true", found.offset
    else:
        return []
    compliance = [cid for cid in (_PUBLIC_ACCESS_CIS.get(res.rtype),) if cid] + ["NIST-AC-4", "NIST-SC-7"]
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-105",
            severity="high",
            title="Azure database server allows public network access",
            message=(
                f"Database server '{res.rname}' ({res.rtype}) {state}; the endpoint is reachable from the "
                "internet subject only to firewall rules."
            ),
            compliance=compliance,
            remediation="Set public_network_access_enabled = false and connect through a private endpoint or delegated subnet.",
            offset=offset,
        )
    ]


def tf_sec_106(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-106: database server does not enforce SSL or accepts TLS below 1.2."""
    ssl = attr(res.block, "ssl_enforcement_enabled")
    if res.rtype in AZURE_SINGLE_SERVER_TYPES and ssl is not None and ssl.boolean is False:
        compliance = [cid for cid in (_SSL_ENFORCEMENT_CIS.get(res.rtype),) if cid] + ["NIST-SC-8"]
        return [_weak_transport(res, "sets ssl_enforcement_enabled = false, allowing plaintext client connections", compliance, ssl.offset)]
    for arg in ("ssl_minimal_tls_version_enforced", "minimum_tls_version"):
        found = attr(res.block, arg)
        if found is not None and found.string in _WEAK_DB_TLS:
            return [_weak_transport(res, f'sets {arg} = "{found.string}"; TLS below 1.2 is deprecated', ["NIST-SC-8"], found.offset)]
    return []


def _weak_transport(res: TfResource, state: str, compliance: list[str], offset: int) -> IaCFinding:
    return tf_finding(
        res,
        rule_id="TF-SEC-106",
        severity="high",
        title="Azure database server does not enforce TLS 1.2",
        message=f"Database server '{res.rname}' ({res.rtype}) {state}.",
        compliance=compliance,
        remediation='Set ssl_enforcement_enabled = true and the minimum TLS version to "TLS1_2" (minimum_tls_version = "1.2" on SQL).',
        offset=offset,
    )


def tf_sec_107(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-107: Key Vault without purge protection."""
    found = attr(res.block, "purge_protection_enabled")
    if found is not None and found.boolean is True:
        return []
    state = "sets purge_protection_enabled = false" if found is not None else "does not enable purge_protection_enabled"
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-107",
            severity="high",
            title="Azure Key Vault is not purge protected",
            message=(
                f"Key Vault '{res.rname}' {state}; a compromised principal can permanently purge keys and "
                "secrets during the soft-delete window."
            ),
            compliance=["CIS-Azure-8.3", "NIST-SC-12"],
            remediation="Set purge_protection_enabled = true and soft_delete_retention_days = 90.",
            offset=found.offset if found is not None else None,
        )
    ]


def tf_sec_108(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-108: managed disk without customer-managed key encryption."""
    if any(attr(res.block, arg) is not None or nested_block(res.block, arg) is not None for arg in _DISK_ENCRYPTION_ARGS):
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-108",
            severity="medium",
            title="Azure managed disk relies on platform-managed keys only",
            message=(
                f"Managed disk '{res.rname}' has no disk_encryption_set_id or encryption_settings; "
                "data is encrypted only with platform-managed keys."
            ),
            compliance=["CIS-Azure-7.3", "NIST-SC-28"],
            remediation="Reference an azurerm_disk_encryption_set via disk_encryption_set_id to use a customer-managed key.",
        )
    ]


def tf_sec_111(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-111: SQL server without an extended auditing policy in the same configuration."""
    targets: set[str] = set()
    unresolved = False
    for m in _AUDIT_POLICY_RE.finditer(res.content):
        body = extract_block(res.content, m.end())
        ref = _SERVER_REF_RE.search(body)
        if ref is None:
            unresolved = True
        else:
            targets.add(ref.group(1))
    if unresolved or res.rname in targets:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-111",
            severity="medium",
            title="Azure SQL server auditing not configured",
            message=(
                f"SQL server '{res.rname}' has no azurerm_mssql_server_extended_auditing_policy in this "
                "configuration; logins and queries are not audited."
            ),
            compliance=["CIS-Azure-4.1.1", "NIST-AU-12"],
            remediation="Add an azurerm_mssql_server_extended_auditing_policy targeting the server with a 90+ day retention.",
        )
    ]


def tf_sec_112(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-112: SQL database with Transparent Data Encryption disabled."""
    found = attr(res.block, "transparent_data_encryption_enabled")
    if found is None or found.boolean is not False:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-112",
            severity="high",
            title="Azure SQL database TDE disabled",
            message=(
                f"SQL database '{res.rname}' sets transparent_data_encryption_enabled = false; "
                "data files and backups are stored unencrypted."
            ),
            compliance=["CIS-Azure-4.1.2", "NIST-SC-28"],
            remediation="Remove transparent_data_encryption_enabled = false (the default is true).",
            offset=found.offset,
        )
    ]
