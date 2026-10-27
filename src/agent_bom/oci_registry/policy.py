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
from agent_bom.oci_registry.reference import ImageReference
from agent_bom.runtime.egress_transport import UnsafeDestinationError, validate_literal_destination

ALLOWLIST_ENV = "AGENT_BOM_REGISTRY_ALLOWLIST"


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
        """Whether ``registry`` (``host[:port]``) is inside the allowlist (always true without one)."""
        if not self.allowlist:
            return True
        host = registry.lower()
        return host in self.allowlist or host.rsplit(":", 1)[0] in self.allowlist

    def refusal(self, ref: ImageReference) -> str | None:
        """Why a server-side scan may not contact ``ref``'s registry (``None`` when it may)."""
        if not self.server:
            return None
        if not self.permits_host(ref.registry):
            return f"registry host is not in {ALLOWLIST_ENV}"
        host = ref.registry.rsplit(":", 1)[0].lower()
        if host == "localhost" or host.endswith(".localhost"):
            return "loopback registries are not reachable from server-side scans"
        try:
            validate_literal_destination(host)
        except UnsafeDestinationError:
            return "registry address is loopback, private, link-local, CGNAT or cloud metadata"
        return None


LOCAL_POLICY = RegistryPolicy()
