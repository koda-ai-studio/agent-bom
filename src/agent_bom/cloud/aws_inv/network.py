"""AWS VPC network-edge rows and public IP discovery for the inventory facade."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from ._base import record_discovery_failure


def _discover_vpcs(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate VPCs (read-only). Become ``CLOUD_RESOURCE`` network nodes."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("ec2", region_name=region)
        for vpc in client.describe_vpcs().get("Vpcs", []):
            vpc_id = str(vpc.get("VpcId", "") or "")
            if not vpc_id:
                continue
            tags = {str(t.get("Key", "")): str(t.get("Value", "")) for t in vpc.get("Tags", []) if t.get("Key")}
            out.append(
                {
                    # vpc_id is the stable node identifier; the Name tag is display-only.
                    "name": vpc_id,
                    "display_name": tags.get("Name") or vpc_id,
                    "vpc_id": vpc_id,
                    "cidr": str(vpc.get("CidrBlock", "") or ""),
                    "is_default": bool(vpc.get("IsDefault")),
                    "tags": tags,
                    "account_id": account_id or "",
                    "location": region,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed VPC list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="VPCs", permission="ec2:DescribeVpcs", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _ec2_pages(ec2: Any, operation: str, key: str) -> Iterator[Any]:
    """Yield every item under ``key`` across the pages of a paginated EC2 describe call."""
    paginator = ec2.get_paginator(operation)
    for page in paginator.paginate():
        yield from page.get(key, []) or []


def _ec2_items(ec2: Any, operation: str, key: str) -> Iterator[Any]:
    """Yield every item under ``key`` from a single (unpaginated) EC2 describe call."""
    yield from getattr(ec2, operation)().get(key, []) or []


def _collect_edge_rows(
    rows: list[dict[str, Any]],
    items: Iterator[Any],
    normalize: Callable[[Any], dict[str, Any] | None],
    *,
    resource_type: str,
    permission: str,
    warnings: list[str],
    missing: list[dict[str, str]] | None,
) -> bool:
    """Append each normalized item to ``rows``; one failing resource type never sinks the others."""
    try:
        for item in items:
            row = normalize(item)
            if row is not None:
                rows.append(row)
        return True
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc, resource_type=resource_type, permission=permission, cloud="aws", warnings=warnings, missing=missing
        )
        return False


def _route_table_row(rt: Any, region: str, account_id: str | None) -> dict[str, Any] | None:
    rt_id = str(rt.get("RouteTableId") or "")
    if not rt_id:
        return None
    routes = [
        {key: row[key] for key in ("DestinationCidrBlock", "DestinationIpv6CidrBlock", "GatewayId", "NatGatewayId", "State") if key in row}
        for row in rt.get("Routes", []) or []
        if isinstance(row, dict)
    ]
    associations = [
        {key: row[key] for key in ("SubnetId", "Main", "AssociationState") if key in row}
        for row in rt.get("Associations", []) or []
        if isinstance(row, dict)
    ]
    return {
        "id": rt_id,
        "name": rt_id,
        "vpc_id": str(rt.get("VpcId") or ""),
        "has_internet_route": bool(_active_internet_gateways(routes)),
        "routes": routes,
        "associations": associations,
        "location": region,
        "account_id": account_id or "",
    }


def _active_internet_gateways(routes: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(route["GatewayId"])
            for route in routes
            if str(route.get("GatewayId") or "").startswith("igw-")
            and route.get("State") == "active"
            and (route.get("DestinationCidrBlock") == "0.0.0.0/0" or route.get("DestinationIpv6CidrBlock") == "::/0")
        }
    )


def _subnet_row(sn: Any, region: str, account_id: str | None) -> dict[str, Any] | None:
    sn_id = str(sn.get("SubnetId") or "")
    if not sn_id:
        return None
    tags = {str(t.get("Key", "")): str(t.get("Value", "")) for t in sn.get("Tags", []) if t.get("Key")}
    return {
        "id": sn_id,
        "name": tags.get("Name", sn_id),
        "vpc_id": str(sn.get("VpcId") or ""),
        "cidr": str(sn.get("CidrBlock") or ""),
        "is_public": None,
        "location": str(sn.get("AvailabilityZone") or region),
        "account_id": account_id or "",
    }


def _apply_subnet_routes(out: dict[str, list[dict[str, Any]]], *, complete: bool) -> None:
    """Resolve explicit subnet association before the VPC's main route table."""
    for subnet in out["subnets"]:
        subnet["is_public"] = None
        subnet["route_table_id"] = None
        subnet["internet_gateway_ids"] = []
        if not complete:
            continue
        explicit, defaults = [], []
        uncertain = False
        for table in out["route_tables"]:
            if not subnet.get("vpc_id") or table.get("vpc_id") != subnet["vpc_id"]:
                continue
            for association in table.get("associations", []):
                state = (association.get("AssociationState") or {}).get("State")
                if state not in (None, "associated"):
                    if association.get("SubnetId") == subnet["id"] or association.get("Main") is True:
                        uncertain = True
                    continue
                if association.get("SubnetId") == subnet["id"]:
                    explicit.append(table)
                elif association.get("Main") is True:
                    defaults.append(table)
        if uncertain:
            continue
        candidates = explicit or defaults
        candidates = list({table["id"]: table for table in candidates}.values())
        if len(candidates) != 1:
            continue
        table = candidates[0]
        routes = table.get("routes", [])
        subnet["route_table_id"] = table["id"]
        gateways = _active_internet_gateways(routes)
        subnet["internet_gateway_ids"] = gateways
        subnet["is_public"] = (
            True if gateways else None if any(route.get("State") not in {"active", "blackhole"} for route in routes) else False
        )


def _network_interface_row(eni: Any, region: str, account_id: str | None) -> dict[str, Any] | None:
    eni_id = str(eni.get("NetworkInterfaceId", "") or "")
    if not eni_id:
        return None
    sg_ids = [str(g.get("GroupId", "")) for g in eni.get("Groups", []) or [] if isinstance(g, dict) and g.get("GroupId")]
    attachment = eni.get("Attachment") or {}
    association = eni.get("Association") or {}
    return {
        "id": eni_id,
        "name": eni_id,
        "instance_id": str(attachment.get("InstanceId", "") or ""),
        "subnet_id": str(eni.get("SubnetId", "") or ""),
        "vpc_id": str(eni.get("VpcId", "") or ""),
        "security_group_ids": sg_ids,
        "private_ip": str(eni.get("PrivateIpAddress", "") or ""),
        "public_ip": str(association.get("PublicIp", "") or ""),
        "location": region,
        "account_id": account_id or "",
    }


def _nat_gateway_row(nat: Any, region: str, account_id: str | None) -> dict[str, Any] | None:
    nat_id = str(nat.get("NatGatewayId", "") or "")
    if not nat_id:
        return None
    return {
        "id": nat_id,
        "name": nat_id,
        "vpc_id": str(nat.get("VpcId", "") or ""),
        "subnet_id": str(nat.get("SubnetId", "") or ""),
        "connectivity": str(nat.get("ConnectivityType", "") or "public"),
        "location": region,
        "account_id": account_id or "",
    }


def _internet_gateway_row(igw: Any, region: str, account_id: str | None, *, id_key: str, kind: str) -> dict[str, Any] | None:
    igw_id = str(igw.get(id_key, "") or "")
    if not igw_id:
        return None
    vpc_ids = [str(a.get("VpcId", "")) for a in igw.get("Attachments", []) or [] if isinstance(a, dict) and a.get("VpcId")]
    row: dict[str, Any] = {"id": igw_id, "name": igw_id, "vpc_id": vpc_ids[0] if vpc_ids else "", "kind": kind}
    if kind == "internet-gateway":
        row["internet_exposed"] = True
    row.update(location=region, account_id=account_id or "")
    return row


def _vpc_endpoint_row(vpe: Any, region: str, account_id: str | None) -> dict[str, Any] | None:
    vpe_id = str(vpe.get("VpcEndpointId", "") or "")
    if not vpe_id:
        return None
    return {
        "id": vpe_id,
        "name": str(vpe.get("ServiceName", "") or vpe_id),
        "vpc_id": str(vpe.get("VpcId", "") or ""),
        "endpoint_type": str(vpe.get("VpcEndpointType", "") or ""),
        "location": region,
        "account_id": account_id or "",
    }


def _network_acl_exposure(acl: Any) -> list[dict[str, Any]]:
    network_exposure: list[dict[str, Any]] = []
    for entry in acl.get("Entries", []) or []:
        if not isinstance(entry, dict) or entry.get("Egress"):
            continue
        if str(entry.get("RuleAction", "")).lower() != "allow":
            continue
        cidr = str(entry.get("CidrBlock", "") or entry.get("Ipv6CidrBlock", "") or "")
        if cidr not in ("0.0.0.0/0", "::/0"):
            continue
        network_exposure.append(
            {
                "cidr": cidr,
                "from_port": entry.get("PortRange", {}).get("From") if isinstance(entry.get("PortRange"), dict) else None,
                "to_port": entry.get("PortRange", {}).get("To") if isinstance(entry.get("PortRange"), dict) else None,
                "protocol": str(entry.get("Protocol", "") or ""),
                "scope": "internet",
            }
        )
    return network_exposure


def _network_acl_row(acl: Any, region: str, account_id: str | None) -> dict[str, Any] | None:
    acl_id = str(acl.get("NetworkAclId", "") or "")
    if not acl_id:
        return None
    subnet_ids = sorted(
        {
            str(assoc.get("SubnetId", "") or "")
            for assoc in acl.get("Associations", []) or []
            if isinstance(assoc, dict) and assoc.get("SubnetId")
        }
    )
    network_exposure = _network_acl_exposure(acl)
    return {
        "id": acl_id,
        "name": acl_id,
        "vpc_id": str(acl.get("VpcId", "") or ""),
        "is_default": bool(acl.get("IsDefault")),
        "subnet_ids": subnet_ids,
        # The AWS default NACL is allow-all inbound by design, so
        # its permissive rules alone are not internet exposure —
        # only flag non-default NACLs (downstream public-subnet
        # gate is the primary guard).
        "internet_exposed": bool(network_exposure) and not bool(acl.get("IsDefault")),
        "network_exposure": network_exposure,
        "location": region,
        "account_id": account_id or "",
    }


_EdgeStage = tuple[str, Iterator[Any], Callable[[Any], dict[str, Any] | None], str, str]


def _network_edge_stages(ec2: Any, region: str, account_id: str | None) -> tuple[_EdgeStage, ...]:
    """(output key, item source, normalizer, resource type, permission) per edge resource, in run order."""
    # Route tables first so subnet public/private classification can use them.
    return (
        (
            "route_tables",
            _ec2_pages(ec2, "describe_route_tables", "RouteTables"),
            lambda rt: _route_table_row(rt, region, account_id),
            "route tables",
            "ec2:DescribeRouteTables",
        ),
        (
            "subnets",
            _ec2_pages(ec2, "describe_subnets", "Subnets"),
            lambda sn: _subnet_row(sn, region, account_id),
            "subnets",
            "ec2:DescribeSubnets",
        ),
        (
            "network_interfaces",
            _ec2_pages(ec2, "describe_network_interfaces", "NetworkInterfaces"),
            lambda eni: _network_interface_row(eni, region, account_id),
            "network interfaces",
            "ec2:DescribeNetworkInterfaces",
        ),
        (
            "nat_gateways",
            _ec2_pages(ec2, "describe_nat_gateways", "NatGateways"),
            lambda nat: _nat_gateway_row(nat, region, account_id),
            "NAT gateways",
            "ec2:DescribeNatGateways",
        ),
        (
            "internet_gateways",
            _ec2_items(ec2, "describe_internet_gateways", "InternetGateways"),
            lambda igw: _internet_gateway_row(igw, region, account_id, id_key="InternetGatewayId", kind="internet-gateway"),
            "internet gateways",
            "ec2:DescribeInternetGateways",
        ),
        (
            "internet_gateways",
            _ec2_items(ec2, "describe_egress_only_internet_gateways", "EgressOnlyInternetGateways"),
            lambda eigw: _internet_gateway_row(
                eigw, region, account_id, id_key="EgressOnlyInternetGatewayId", kind="egress-only-internet-gateway"
            ),
            "egress-only internet gateways",
            "ec2:DescribeEgressOnlyInternetGateways",
        ),
        (
            "vpc_endpoints",
            _ec2_pages(ec2, "describe_vpc_endpoints", "VpcEndpoints"),
            lambda vpe: _vpc_endpoint_row(vpe, region, account_id),
            "VPC endpoints",
            "ec2:DescribeVpcEndpoints",
        ),
        (
            "network_acls",
            _ec2_pages(ec2, "describe_network_acls", "NetworkAcls"),
            lambda acl: _network_acl_row(acl, region, account_id),
            "network ACLs",
            "ec2:DescribeNetworkAcls",
        ),
    )


def _discover_network_edge(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Enumerate VPC plumbing (read-only): ENIs, NAT/internet gateways, VPC
    endpoints, subnets, route tables, and network ACLs.

    A subnet is marked ``is_public`` when a route table associated with it routes
    ``0.0.0.0/0`` to an internet gateway — the same internet-reachability
    classifier the GCP firewall path uses, applied to the AWS network fabric.
    """
    out: dict[str, list[dict[str, Any]]] = {
        "network_interfaces": [],
        "subnets": [],
        "nat_gateways": [],
        "internet_gateways": [],
        "vpc_endpoints": [],
        "route_tables": [],
        "network_acls": [],
    }
    ec2 = session.client("ec2", region_name=region)
    route_tables_complete = False
    # Stages run in order, each isolated so one denied describe call never sinks the others.
    for key, items, normalize, resource_type, permission in _network_edge_stages(ec2, region, account_id):
        complete = _collect_edge_rows(
            out[key], items, normalize, resource_type=resource_type, permission=permission, warnings=warnings, missing=missing
        )
        if key == "route_tables":
            route_tables_complete = complete
    _apply_subnet_routes(out, complete=route_tables_complete)
    return out


def _discover_ip_addresses(
    session: Any,
    region: str,
    *,
    account_id: str | None,
    network_interfaces: list[dict[str, Any]],
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate Elastic IPs plus the public IPs bound to ENIs (read-only).

    Every internet-facing address is inventoried and attributable so an exposed
    address can be tied back to the resource it fronts. Elastic IPs come from
    ``describe_addresses``; ephemeral public IPs are read from the already-
    discovered ENIs (no extra call).
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        ec2 = session.client("ec2", region_name=region)
        for addr in ec2.describe_addresses().get("Addresses", []) or []:
            ip = str(addr.get("PublicIp", "") or "")
            if not ip or ip in seen:
                continue
            seen.add(ip)
            attached = str(addr.get("InstanceId", "") or addr.get("NetworkInterfaceId", "") or "")
            out.append(
                {
                    "address": ip,
                    "kind": "elastic",
                    "attached_to": attached,
                    "allocation_id": str(addr.get("AllocationId", "") or ""),
                    "location": region,
                    "account_id": account_id or "",
                }
            )
    except Exception as exc:  # noqa: BLE001
        record_discovery_failure(
            exc=exc, resource_type="Elastic IPs", permission="ec2:DescribeAddresses", cloud="aws", warnings=warnings, missing=missing
        )

    for eni in network_interfaces:
        ip = str(eni.get("public_ip", "") or "")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out.append(
            {
                "address": ip,
                "kind": "public",
                "attached_to": str(eni.get("instance_id", "") or eni.get("id", "") or ""),
                "location": region,
                "account_id": account_id or "",
            }
        )
    return out
