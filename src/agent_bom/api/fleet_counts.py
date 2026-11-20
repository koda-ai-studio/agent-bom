"""Per-agent fleet counts, each package, credential variable and advisory once."""

from __future__ import annotations

from typing import Any

from agent_bom.core.packages import canonical_package_key


def _field(item: Any, name: str) -> Any:
    return item.get(name) if isinstance(item, dict) else getattr(item, name, None)


def distinct_counts(servers: list[Any]) -> tuple[int, int, int]:
    """Packages, credential names and vulnerabilities an agent has, each counted once.

    Servers often share a package or a credential variable; summing per server
    counted those once per server. A vulnerability is one (package, advisory)
    pair; a server that reports only its total adds that total.
    """
    packages: set[str] = set()
    credentials: set[str] = set()
    advisories: set[tuple[str, str]] = set()
    unattributed = 0
    for server in servers:
        listed = 0
        for package in _field(server, "packages") or []:
            key = canonical_package_key(
                str(_field(package, "name") or ""),
                str(_field(package, "version") or ""),
                str(_field(package, "ecosystem") or ""),
                _field(package, "purl"),
            )
            packages.add(key)
            for vulnerability in _field(package, "vulnerabilities") or []:
                if advisory := _field(vulnerability, "id"):
                    advisories.add((key, str(advisory)))
                    listed += 1
        credentials.update(str(name) for name in _field(server, "credential_names") or [])
        if not listed:
            unattributed += int(_field(server, "total_vulnerabilities") or 0)
    return len(packages), len(credentials), len(advisories) + unattributed
