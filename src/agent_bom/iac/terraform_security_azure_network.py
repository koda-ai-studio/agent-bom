"""Azure network rules: NSG internet exposure, VM public IPs, NSG flow logs (TF-SEC-104, 109, 110)."""

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

# Service tags and literals that mean "any internet source" in an NSG rule.
_ANY_SOURCE = frozenset({"*", "0.0.0.0/0", "0.0.0.0", "::/0", "internet", "any"})
_MIN_FLOW_LOG_RETENTION_DAYS = 90


def tf_sec_104(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-104: NSG allows inbound traffic from any internet source."""
    if res.rtype == "azurerm_network_security_rule":
        return _nsg_rule(res, res.block, None)
    findings: list[IaCFinding] = []
    for offset, body in nested_blocks(res.block, "security_rule"):
        findings.extend(_nsg_rule(res, body, offset))
    return findings


def _nsg_rule(res: TfResource, body: str, offset: int | None) -> list[IaCFinding]:
    direction = (attr_string(body, "direction") or "").lower()
    access = (attr_string(body, "access") or "").lower()
    if direction != "inbound" or access != "allow" or not _any_source(body):
        return []
    protocol = (attr_string(body, "protocol") or "*").lower()
    specs = _port_specs(body)
    if protocol == "tcp" and port_specs_only_web(specs):
        return []
    compliance = ["NIST-AC-4"]
    if protocol != "udp" and any(port_spec_covers(s, 22) for s in specs):
        compliance.insert(0, "CIS-Azure-6.2")
    if protocol != "udp" and any(port_spec_covers(s, 3389) for s in specs):
        compliance.insert(0, "CIS-Azure-6.1")
    if protocol in {"udp", "*"}:
        compliance.insert(-1, "CIS-Azure-6.4")
    critical = any(c.startswith("CIS-Azure-6.") for c in compliance)
    ports = ", ".join(specs) or "*"
    rule_name = attr_string(body, "name") or res.rname
    return [
        tf_finding(
            res,
            rule_id="TF-SEC-104",
            severity="critical" if critical else "high",
            title="Azure NSG rule open to the internet",
            message=(
                f"NSG rule '{rule_name}' on '{res.rname}' allows inbound {protocol} traffic to port(s) {ports} "
                "from any source. Management ports and broad allow rules reachable from the internet are a primary intrusion path."
            ),
            compliance=sorted(set(compliance), key=compliance.index),
            remediation="Restrict source_address_prefix(es) to known CIDRs or service tags; use Azure Bastion or JIT access for SSH/RDP.",
            offset=offset,
        )
    ]


def _any_source(body: str) -> bool:
    single = attr_string(body, "source_address_prefix")
    if single is not None and single.lower() in _ANY_SOURCE:
        return True
    return any(prefix.lower() in _ANY_SOURCE for prefix in attr_strings(body, "source_address_prefixes") or [])


def _port_specs(body: str) -> list[str]:
    single = attr_string(body, "destination_port_range")
    specs = [single] if single is not None else []
    specs.extend(attr_strings(body, "destination_port_ranges") or [])
    return specs or ["*"]


def tf_sec_109(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-109: network interface attaches a public IP address."""
    findings: list[IaCFinding] = []
    for offset, body in nested_blocks(res.block, "ip_configuration"):
        public_ip = attr(body, "public_ip_address_id")
        if public_ip is None or public_ip.raw.strip().lower() == "null":
            continue
        findings.append(
            tf_finding(
                res,
                rule_id="TF-SEC-109",
                severity="medium",
                title="Azure VM network interface has a public IP",
                message=(
                    f"Network interface '{res.rname}' attaches a public IP, exposing the VM directly to the internet. "
                    "Prefer private IPs behind a load balancer, Bastion, or NAT gateway."
                ),
                compliance=["NIST-SC-7", "NIST-AC-4"],
                remediation="Remove public_ip_address_id from ip_configuration; front the VM with a load balancer or Azure Bastion.",
                offset=offset + public_ip.offset,
            )
        )
    return findings


def tf_sec_110(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-110: NSG flow log disabled or retained for less than 90 days."""
    enabled = attr(res.block, "enabled")
    if enabled is not None and enabled.boolean is False:
        return [_flow_log(res, "is disabled (enabled = false)", enabled.offset)]
    retention = nested_block(res.block, "retention_policy")
    if retention is None:
        return []
    offset, body = retention
    if attr_bool(body, "enabled") is False:
        return [_flow_log(res, "has retention disabled", offset)]
    days = attr(body, "days")
    if days is not None and days.raw.strip().isdigit() and 0 < int(days.raw.strip()) < _MIN_FLOW_LOG_RETENTION_DAYS:
        return [_flow_log(res, f"retains records for {days.raw.strip()} days", offset + days.offset)]
    return []


def _flow_log(res: TfResource, state: str, offset: int) -> IaCFinding:
    return tf_finding(
        res,
        rule_id="TF-SEC-110",
        severity="medium",
        title="Azure NSG flow log disabled or short retention",
        message=(
            f"Network Watcher flow log '{res.rname}' {state}; network forensics need at least "
            f"{_MIN_FLOW_LOG_RETENTION_DAYS} days of flow records."
        ),
        compliance=["NIST-AU-12", "NIST-AU-11"],
        remediation="Set enabled = true and retention_policy { enabled = true, days >= 90 } (0 keeps logs indefinitely).",
        offset=offset,
    )
