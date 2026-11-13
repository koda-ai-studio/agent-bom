"""Hostname resolution for the egress rebinding check, tolerant of proxy-only networks."""

from __future__ import annotations

import logging
import socket
import threading
import time
from urllib.request import getproxies, proxy_bypass

logger = logging.getLogger(__name__)

#: ``socket.getaddrinfo`` has no timeout of its own; a stalled resolver must not
#: hold an outbound request (and the scan behind it) longer than its HTTP budget.
RESOLUTION_TIMEOUT_SECONDS = 5.0
#: A validated answer is reused briefly so a scan making hundreds of requests to
#: one registry resolves it once. Failures are never cached.
RESOLUTION_CACHE_TTL_SECONDS = 60.0
_resolution_cache: dict[str, tuple[float, list[tuple]]] = {}
_resolution_lock = threading.Lock()
_monotonic = time.monotonic


def clear_resolution_cache() -> None:
    with _resolution_lock:
        _resolution_cache.clear()


def _getaddrinfo_bounded(hostname: str) -> list[tuple]:
    """Resolve on a daemon thread so a hung lookup cannot outlive the timeout."""
    outcome: dict[str, object] = {}
    done = threading.Event()

    def _resolve() -> None:
        try:
            outcome["value"] = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            outcome["error"] = exc
        finally:
            done.set()

    threading.Thread(target=_resolve, name="egress-resolve", daemon=True).start()
    if not done.wait(RESOLUTION_TIMEOUT_SECONDS):
        raise TimeoutError(hostname)
    error = outcome.get("error")
    if isinstance(error, OSError):
        raise error
    value = outcome.get("value")
    return list(value) if isinstance(value, list) else []


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
    now = _monotonic()
    with _resolution_lock:
        cached = _resolution_cache.get(hostname)
    if cached is not None and now - cached[0] < RESOLUTION_CACHE_TTL_SECONDS:
        return list(cached[1])
    try:
        addrinfos = _getaddrinfo_bounded(hostname)
    except TimeoutError:
        if egress_proxy_applies(hostname):
            logger.debug("Hostname resolution timed out locally; egress proxy applies")
            return []
        raise error(f"Hostname resolution timed out after {RESOLUTION_TIMEOUT_SECONDS:g}s: {hostname}") from None
    except socket.gaierror:
        if egress_proxy_applies(hostname):
            logger.debug("Hostname not resolvable locally; egress proxy applies")
            return []
        raise error(f"Cannot resolve hostname: {hostname}")
    with _resolution_lock:
        _resolution_cache[hostname] = (now, list(addrinfos))
    return addrinfos
