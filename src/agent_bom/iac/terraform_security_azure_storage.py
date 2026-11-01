"""Azure storage account rules (TF-SEC-101..103).

Attribute names follow the azurerm provider docs: v3 ``allow_blob_public_access`` /
``enable_https_traffic_only`` and v4 ``allow_nested_items_to_be_public`` /
``https_traffic_only_enabled`` are both recognised. Absence is never reported
as public because the provider default changed between major versions.
"""

from __future__ import annotations

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource
from agent_bom.iac.terraform_security_hcl import attr, tf_finding

_PUBLIC_ACCESS_FLAGS = ("allow_blob_public_access", "allow_nested_items_to_be_public")
_HTTPS_ONLY_FLAGS = ("enable_https_traffic_only", "https_traffic_only_enabled")
_WEAK_TLS = frozenset({"TLS1_0", "TLS1_1"})
_PUBLIC_CONTAINER_LEVELS = frozenset({"blob", "container"})


def tf_sec_101(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-101: storage account or container allows anonymous public blob access."""
    if res.rtype == "azurerm_storage_container":
        level = attr(res.block, "container_access_type")
        if level is None or level.string not in _PUBLIC_CONTAINER_LEVELS:
            return []
        return [_public_access(res, f'container_access_type = "{level.string}"', level.offset)]
    for flag in _PUBLIC_ACCESS_FLAGS:
        found = attr(res.block, flag)
        if found is not None and found.boolean is True:
            return [_public_access(res, f"{flag} = true", found.offset)]
    return []


def _public_access(res: TfResource, setting: str, offset: int) -> IaCFinding:
    return tf_finding(
        res,
        rule_id="TF-SEC-101",
        severity="critical",
        title="Azure storage allows anonymous public blob access",
        message=(
            f"Resource '{res.rname}' ({res.rtype}) sets {setting}, which lets anonymous "
            "internet clients read blobs in public containers. Public storage is a top cloud breach vector."
        ),
        compliance=["CIS-Azure-3.7", "NIST-AC-3"],
        remediation="Set allow_nested_items_to_be_public = false (allow_blob_public_access on azurerm v3) and keep containers private.",
        offset=offset,
    )


def tf_sec_102(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-102: storage account does not require HTTPS (secure transfer)."""
    for flag in _HTTPS_ONLY_FLAGS:
        found = attr(res.block, flag)
        if found is not None and found.boolean is False:
            return [
                tf_finding(
                    res,
                    rule_id="TF-SEC-102",
                    severity="high",
                    title="Azure storage account allows unencrypted HTTP traffic",
                    message=(
                        f"Storage account '{res.rname}' sets {flag} = false, so blob, file, queue and table "
                        "requests may travel over plaintext HTTP."
                    ),
                    compliance=["CIS-Azure-3.1", "NIST-SC-8"],
                    remediation="Set https_traffic_only_enabled = true (enable_https_traffic_only on azurerm v3).",
                    offset=found.offset,
                )
            ]
    return []


def tf_sec_103(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-103: storage account minimum TLS version below 1.2."""
    found = attr(res.block, "min_tls_version")
    if found is None or found.string not in _WEAK_TLS:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-103",
            severity="high",
            title="Azure storage account accepts TLS below 1.2",
            message=f"Storage account '{res.rname}' sets min_tls_version = \"{found.string}\"; TLS 1.0 and 1.1 are deprecated protocols.",
            compliance=["CIS-Azure-3.15", "NIST-SC-8"],
            remediation='Set min_tls_version = "TLS1_2".',
            offset=found.offset,
        )
    ]
