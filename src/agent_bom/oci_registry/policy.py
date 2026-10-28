"""Registry egress policy: what a scan may contact and with which credentials.

The local CLI runs as the operator, so it may reach a loopback registry over
plain HTTP and use the operator's own Docker credentials. A server-side scan
(API scan jobs, the MCP server) acts on a reference somebody else supplied, so
it is anonymous-only, HTTPS-only, refuses loopback/private/link-local/CGNAT and
metadata destinations (literals here, DNS answers at connect time), honours
``AGENT_BOM_REGISTRY_ALLOWLIST`` and reports upstream failures without their
HTTP status.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_bom.core.settings import env_raw
from agent_bom.oci_registry.reference import DOCKER_HUB_ALIASES, ImageReference
from agent_bom.runtime.egress_transport import UnsafeDestinationError, validate_literal_destination

ALLOWLIST_ENV = "AGENT_BOM_REGISTRY_ALLOWLIST"
# Hub references normalise to registry-1.docker.io and its bearer tokens come from
# auth.docker.io, so any one Hub name in the allowlist admits the whole family.
_DOCKER_HUB_HOSTS = DOCKER_HUB_ALIASES | {"auth.docker.io"}


def _bare_host(registry: str) -> str:
    """``host`` from ``host[:port]``, lower-cased."""
    return registry.lower().rsplit(":", 1)[0]


@dataclass(frozen=True)
class RegistryPolicy:
    server: bool = False
    allowlist: frozenset[str] = frozenset()

    @classmethod
    def for_server(cls) -> RegistryPolicy:
        raw = env_raw(ALLOWLIST_ENV) or ""
        return cls(server=True, allowlist=frozenset(item.strip().lower() for item in raw.split(",") if item.strip()))

    def allows_plain_http(self, ref: ImageReference) -> bool:
        return ref.allows_plain_http and not self.server

    def permits_host(self, registry: str) -> bool:
        """Whether ``registry`` (``host[:port]``) is inside the allowlist (always true without one).

        Any Docker Hub alias in the allowlist admits every Hub host, since a Hub
        reference is always rewritten to ``registry-1.docker.io``.
        """
        if not self.allowlist:
            return True
        host = registry.lower()
        if host in self.allowlist or _bare_host(host) in self.allowlist:
            return True
        return _bare_host(host) in _DOCKER_HUB_HOSTS and not self.allowlist.isdisjoint(_DOCKER_HUB_HOSTS)

    def realm_refusal(self, ref: ImageReference, realm_host: str) -> str | None:
        """Why a server-side scan may not fetch a bearer token from ``realm_host`` (``None`` when it may).

        Only enforced when an allowlist is configured: the realm must be the
        registry itself or an allowlisted host, so a registry cannot redirect
        credential exchange to an arbitrary destination.
        """
        if not self.server or not self.allowlist:
            return None
        if _bare_host(realm_host) == _bare_host(ref.registry) or self.permits_host(realm_host):
            return None
        return f"token realm host is not in {ALLOWLIST_ENV}"

    def refusal(self, ref: ImageReference) -> str | None:
        """Why a server-side scan may not contact ``ref``'s registry (``None`` when it may)."""
        if not self.server:
            return None
        if not self.permits_host(ref.registry):
            return f"registry host is not in {ALLOWLIST_ENV}"
        host = _bare_host(ref.registry)
        if host == "localhost" or host.endswith(".localhost"):
            return "loopback registries are not reachable from server-side scans"
        try:
            validate_literal_destination(host)
        except UnsafeDestinationError:
            return "registry address is loopback, private, link-local, CGNAT or cloud metadata"
        return None


LOCAL_POLICY = RegistryPolicy()
