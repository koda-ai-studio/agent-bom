"""Hostname resolution for the egress rebinding check, tolerant of proxy-only networks."""

from __future__ import annotations

import logging
import socket
from urllib.request import getproxies, proxy_bypass

logger = logging.getLogger(__name__)


def egress_proxy_applies(hostname: str) -> bool:
    """True when an ``HTTPS_PROXY``/``ALL_PROXY`` environment proxy covers ``hostname``.

    Mirrors the httpx/urllib environment rules, ``NO_PROXY`` included, so the
    answer matches the connection the client will actually make.
    """
    proxies = getproxies()
    if not (proxies.get("https") or proxies.get("all")):
        return False
    try:
        return not proxy_bypass(hostname)
    except Exception:  # noqa: BLE001 - a malformed NO_PROXY must not open egress
        return False


def resolve_egress_hostname(hostname: str, error: type[Exception]) -> list[tuple]:
    """Resolve ``hostname`` for the rebinding check, tolerating proxy-only networks.

    Proxy-only networks resolve names at the proxy, so a local resolution
    failure says nothing about the destination. The proxy is the operator's
    egress policy; the literal-IP and metadata-host checks still apply, and a
    locally resolvable name is still checked. Without a proxy, an unresolvable
    name is refused.
    """
    try:
        return socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        if egress_proxy_applies(hostname):
            logger.debug("Hostname not resolvable locally; egress proxy applies")
            return []
        raise error(f"Cannot resolve hostname: {hostname}")
