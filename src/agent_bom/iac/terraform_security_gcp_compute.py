"""GCP VPC firewall, Compute Engine and subnet rules (TF-SEC-203, 207..211)."""

from __future__ import annotations

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource
from agent_bom.iac.terraform_security_hcl import (
    attr,
    attr_bool,
    attr_string,
    attr_strings,
    nested_block,
    nested_blocks,
    port_spec_covers,
    port_specs_only_web,
    tf_finding,
)

GCE_METADATA_TYPES = frozenset({"google_compute_instance", "google_compute_project_metadata"})
_ANY_RANGE = frozenset({"0.0.0.0/0", "::/0"})
_TRUE_VALUES = frozenset({"true", "1"})
_FALSE_VALUES = frozenset({"false", "0"})


def tf_sec_203(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-203: VPC firewall allows ingress from any internet source."""
    if (attr_string(res.block, "direction") or "INGRESS").upper() != "INGRESS" or attr_bool(res.block, "disabled") is True:
        return []
    if not set(attr_strings(res.block, "source_ranges") or []) & _ANY_RANGE:
        return []
    allows = [body for _, body in nested_blocks(res.block, "allow")]
    if not allows:
        return []
    protocols = {(attr_string(body, "protocol") or "all").lower() for body in allows}
    specs = [spec for body in allows for spec in _allow_ports(body)]
    if protocols == {"tcp"} and port_specs_only_web(specs):
        return []
    compliance = ["NIST-AC-4"]
    if protocols - {"udp", "icmp"} and any(port_spec_covers(s, 22) for s in specs):
        compliance.insert(0, "CIS-GCP-3.6")
    if protocols - {"udp", "icmp"} and any(port_spec_covers(s, 3389) for s in specs):
        compliance.insert(0, "CIS-GCP-3.7")
    if protocols & {"icmp", "all"}:
        compliance.insert(-1, "CIS-GCP-3.8")
    critical = any(c in {"CIS-GCP-3.6", "CIS-GCP-3.7"} for c in compliance)
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-203",
            severity="critical" if critical else "high",
            title="GCP firewall rule open to the internet",
            message=(
                f"Firewall '{res.rname}' allows ingress for {', '.join(sorted(protocols))} on port(s) {', '.join(specs)} "
                "from 0.0.0.0/0 or ::/0. Internet-reachable management ports and broad allow rules are a primary intrusion path."
            ),
            compliance=sorted(set(compliance), key=compliance.index),
            remediation="Restrict source_ranges to known CIDRs or use source_tags/service accounts; reach VMs via IAP TCP forwarding.",
        )
    ]


def _allow_ports(body: str) -> list[str]:
    protocol = (attr_string(body, "protocol") or "all").lower()
    ports = attr_strings(body, "ports")
    if protocol in {"all", "icmp"} or not ports:
        return ["*"]
    return ports


def tf_sec_207(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-207: Compute instance with an external (public) IP."""
    for _, interface in nested_blocks(res.block, "network_interface"):
        public = nested_block(interface, "access_config") or nested_block(interface, "ipv6_access_config")
        if public is not None:
            return [
                tf_finding(
                    res,
                    rule_id="TF-SEC-207",
                    severity="medium",
                    title="GCE instance has a public IP",
                    message=(
                        f"Instance '{res.rname}' declares an access_config block, which assigns an external IP reachable from the internet."
                    ),
                    compliance=["CIS-GCP-4.9", "NIST-SC-7"],
                    remediation="Remove access_config and reach the instance through IAP, a load balancer, or Cloud NAT for egress.",
                )
            ]
    return []


def _metadata_flag(res: TfResource, key: str, values: frozenset[str]) -> tuple[int, str] | None:
    metadata = nested_block(res.block, "metadata")
    if metadata is None:
        return None
    offset, body = metadata
    found = attr(body, key)
    if found is None or found.string is None or found.string.lower() not in values:
        return None
    return offset + found.offset, found.string


def tf_sec_208(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-208: OS Login disabled through instance or project metadata."""
    flag = _metadata_flag(res, "enable-oslogin", _FALSE_VALUES)
    if flag is None:
        return []
    scope = "project" if res.rtype == "google_compute_project_metadata" else "instance"
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-208",
            severity="medium",
            title="GCE OS Login disabled",
            message=(
                f"{scope.capitalize()} metadata on '{res.rname}' sets enable-oslogin = \"{flag[1]}\"; "
                "SSH access falls back to metadata-managed keys without IAM control."
            ),
            compliance=["CIS-GCP-4.4", "NIST-IA-2"],
            remediation='Set enable-oslogin = "true" in project metadata and remove per-instance overrides.',
            offset=flag[0],
        )
    ]


def tf_sec_209(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-209: interactive serial console enabled."""
    flag = _metadata_flag(res, "serial-port-enable", _TRUE_VALUES)
    if flag is None:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-209",
            severity="high",
            title="GCE serial port access enabled",
            message=(
                f"Metadata on '{res.rname}' sets serial-port-enable = \"{flag[1]}\"; the serial console accepts "
                "connections from any IP with no network controls."
            ),
            compliance=["CIS-GCP-4.5", "NIST-AC-17"],
            remediation='Remove serial-port-enable or set it to "false".',
            offset=flag[0],
        )
    ]


def tf_sec_210(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-210: subnetwork without VPC flow logs."""
    purpose = attr_string(res.block, "purpose")
    if (purpose is not None and purpose.upper() != "PRIVATE") or nested_block(res.block, "log_config") is not None:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-210",
            severity="medium",
            title="GCP subnetwork without VPC flow logs",
            message=f"Subnetwork '{res.rname}' has no log_config block; VPC flow logs are disabled, leaving no network forensics trail.",
            compliance=["CIS-GCP-3.9", "NIST-AU-12"],
            remediation='Add a log_config block (e.g. aggregation_interval = "INTERVAL_10_MIN", metadata = "INCLUDE_ALL_METADATA").',
        )
    ]


def tf_sec_211(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-211: Compute instance with IP forwarding enabled."""
    found = attr(res.block, "can_ip_forward")
    if found is None or found.boolean is not True:
        return []
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-211",
            severity="medium",
            title="GCE instance allows IP forwarding",
            message=(
                f"Instance '{res.rname}' sets can_ip_forward = true, letting it route packets for other addresses "
                "and bypass per-VM firewalling."
            ),
            compliance=["CIS-GCP-4.6", "NIST-SC-7"],
            remediation="Set can_ip_forward = false unless the instance is a dedicated NAT or network appliance.",
            offset=found.offset,
        )
    ]
