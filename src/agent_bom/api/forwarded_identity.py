"""Trusted reverse-proxy client identity resolution.

Forwarded address headers are caller-controlled unless the transport peer and
proxy depth are both explicitly configured.  Keep that invariant in one place
so authentication throttles and runtime conditional-access policy cannot drift.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from ipaddress import IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network


def trusted_proxy_hops() -> int:
    """Return the configured positive proxy depth, or zero when invalid."""
    raw = (os.environ.get("AGENT_BOM_TRUSTED_PROXY_HOPS") or "").strip()
    if not raw:
        return 0
    try:
        value = int(raw)
    except ValueError:
        return 0
    return value if 1 <= value <= 32 else 0


def trusted_proxy_networks() -> tuple[IPv4Network | IPv6Network, ...]:
    """Return explicitly trusted transport-peer networks, or none on error."""
    raw = (os.environ.get("AGENT_BOM_TRUSTED_PROXY_CIDRS") or "").strip()
    if not raw:
        return ()
    try:
        return tuple(ip_network(part.strip(), strict=False) for part in raw.split(",") if part.strip())
    except ValueError:
        return ()


def forwarded_for_header(headers: Mapping[str, str]) -> str:
    """Return every X-Forwarded-For line as one list, in received order.

    HTTP treats repeated field lines as one comma-joined value. Reading only
    the first line would let a caller choose the entry a proxy appended to a
    later line, and so choose its own source address.
    """
    getlist = getattr(headers, "getlist", None)
    return ",".join(getlist("x-forwarded-for")) if getlist else str(headers.get("x-forwarded-for", ""))


def peer_is_trusted_proxy(peer_host: str) -> bool:
    """Whether this transport peer is inside the configured proxy networks."""
    try:
        peer = ip_address(peer_host)
    except ValueError:
        return False
    return any(peer in network for network in trusted_proxy_networks())


def failure_limit_source(address: str) -> str:
    """Group an address for failed-authentication limits.

    One IPv6 customer is routinely delegated at least a /64, so a per-address
    limit gives one caller billions of fresh budgets. IPv4-mapped addresses
    count as the IPv4 address they carry.
    """
    try:
        parsed = ip_address(address)
    except ValueError:
        return address
    if isinstance(parsed, IPv6Address):
        if parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        # From the integer, so a zone suffix cannot name a fresh budget.
        return str(ip_network((int(parsed), 64), strict=False))
    return str(parsed)


def resolve_forwarded_client_ip(*, peer_host: str, forwarded_for: str, fallback: str = "") -> str:
    """Resolve a client address only through a declared trusted proxy chain.

    The direct transport peer remains authoritative unless it belongs to an
    allowlisted proxy CIDR and a bounded positive hop count is configured.
    Malformed, oversized, or shorter-than-declared chains fall back to the
    transport peer instead of trusting caller-supplied input.
    """
    host = str(peer_host or fallback)
    hops = trusted_proxy_hops()
    networks = trusted_proxy_networks()
    try:
        peer = ip_address(host)
    except ValueError:
        peer = None
    if hops > 0 and networks and peer is not None and any(peer in network for network in networks):
        forwarded = [part.strip() for part in str(forwarded_for or "").split(",") if part.strip()]
        if hops <= len(forwarded) <= 32:
            candidate = forwarded[-hops]
            try:
                host = str(ip_address(candidate))
            except ValueError:
                pass  # not an IP literal: keep the socket peer address
    return host
