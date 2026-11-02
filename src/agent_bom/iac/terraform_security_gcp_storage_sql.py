"""GCP Cloud Storage and Cloud SQL rules (TF-SEC-201, 202, 204..206).

Attribute names follow the google provider docs; ``require_ssl`` (removed in
provider v6 in favour of ``ssl_mode``) is still recognised for older code.
"""

from __future__ import annotations

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource
from agent_bom.iac.terraform_security_hcl import attr, attr_string, nested_block, nested_blocks, tf_finding

GCS_IAM_TYPES = frozenset({"google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"})
_PUBLIC_PRINCIPALS = frozenset({"allUsers", "allAuthenticatedUsers"})
_ANY_NETWORK = frozenset({"0.0.0.0/0", "::/0"})
_UNENCRYPTED_SSL_MODE = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"


def tf_sec_201(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-201: bucket IAM grants a role to allUsers or allAuthenticatedUsers."""
    member = attr(res.block, "member")
    principals = [member.string] if member is not None and member.string else []
    members = attr(res.block, "members")
    principals.extend((members.strings if members is not None else None) or [])
    public = sorted(set(principals) & _PUBLIC_PRINCIPALS)
    if not public:
        return []
    source = member if member is not None and member.string in _PUBLIC_PRINCIPALS else members
    role = attr_string(res.block, "role") or "a role"
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-201",
            severity="critical",
            title="GCS bucket is publicly accessible",
            message=f"'{res.rname}' grants {role} to {', '.join(public)}, making bucket contents readable by anyone on the internet.",
            compliance=["CIS-GCP-5.1", "NIST-AC-3"],
            remediation='Grant bucket roles to specific principals and set public_access_prevention = "enforced" on the bucket.',
            offset=source.offset if source is not None else None,
        )
    ]


def tf_sec_202(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-202: bucket without uniform bucket-level access."""
    found = attr(res.block, "uniform_bucket_level_access")
    if found is not None and found.boolean is not False:
        return []
    if found is not None:
        state = "sets uniform_bucket_level_access = false"
    else:
        state = "does not set uniform_bucket_level_access (provider default false)"
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-202",
            severity="medium",
            title="GCS bucket allows per-object ACLs",
            message=f"Bucket '{res.rname}' {state}; legacy object ACLs can grant access that bucket IAM does not show.",
            compliance=["CIS-GCP-5.2", "NIST-AC-3"],
            remediation="Set uniform_bucket_level_access = true.",
            offset=found.offset if found is not None else None,
        )
    ]


def _ip_configuration(res: TfResource) -> tuple[int, str] | None:
    settings = nested_block(res.block, "settings")
    if settings is None:
        return None
    offset, body = settings
    ip_config = nested_block(body, "ip_configuration")
    return (offset + ip_config[0], ip_config[1]) if ip_config is not None else None


def tf_sec_204(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-204: Cloud SQL instance with a public IP (critical when open to any network)."""
    ip_config = _ip_configuration(res)
    if ip_config is None:
        return []
    offset, body = ip_config
    public = attr(body, "ipv4_enabled")
    if public is None or public.boolean is not True:
        return []
    open_networks = [
        value for _, network in nested_blocks(body, "authorized_networks") if (value := attr_string(network, "value")) in _ANY_NETWORK
    ]
    exposure = f" and authorizes {', '.join(open_networks)}" if open_networks else ""
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-204",
            severity="critical" if open_networks else "high",
            title="Cloud SQL instance has a public IP",
            message=(
                f"Cloud SQL instance '{res.rname}' sets ipv4_enabled = true{exposure}; "
                "the database endpoint is reachable from the internet."
            ),
            compliance=["CIS-GCP-6.2", "NIST-AC-4"],
            remediation="Set ipv4_enabled = false and connect over private_network (Private Service Connect / private IP).",
            offset=offset + public.offset,
        )
    ]


def tf_sec_205(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-205: Cloud SQL instance does not require SSL for client connections."""
    ip_config = _ip_configuration(res)
    if ip_config is None:
        return []
    offset, body = ip_config
    require_ssl = attr(body, "require_ssl")
    ssl_mode = attr(body, "ssl_mode")
    if require_ssl is not None and require_ssl.boolean is False:
        state, at = "sets require_ssl = false", require_ssl.offset
    elif ssl_mode is not None and ssl_mode.string == _UNENCRYPTED_SSL_MODE:
        state, at = f'sets ssl_mode = "{_UNENCRYPTED_SSL_MODE}"', ssl_mode.offset
    else:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-205",
            severity="high",
            title="Cloud SQL instance accepts unencrypted connections",
            message=f"Cloud SQL instance '{res.rname}' {state}; clients may connect without TLS.",
            compliance=["CIS-GCP-6.1", "NIST-SC-8"],
            remediation='Set ssl_mode = "ENCRYPTED_ONLY" (or "TRUSTED_CLIENT_CERTIFICATE_REQUIRED").',
            offset=offset + at,
        )
    ]


def tf_sec_206(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-206: Cloud SQL instance without automated backups."""
    settings = nested_block(res.block, "settings")
    if settings is None:
        return []
    offset, body = settings
    backup = nested_block(body, "backup_configuration")
    if backup is None:
        state, at = "has no backup_configuration block", None
    elif (enabled := attr(backup[1], "enabled")) is not None and enabled.boolean is False:
        state, at = "sets backup_configuration.enabled = false", offset + backup[0] + enabled.offset
    else:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-206",
            severity="medium",
            title="Cloud SQL instance without automated backups",
            message=f"Cloud SQL instance '{res.rname}' {state}; data cannot be restored after corruption or deletion.",
            compliance=["CIS-GCP-6.3", "NIST-CP-9"],
            remediation="Add backup_configuration { enabled = true } (and point_in_time_recovery_enabled = true for PostgreSQL).",
            offset=at,
        )
    ]
