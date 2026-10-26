"""A version found by the registry's latest lookup is never reported as a pin."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.models import Package
from agent_bom.parsers.python_setup import parse_setup_cfg
from agent_bom.resolver import resolve_package_version


async def _resolve_latest(pkg: Package) -> dict:
    with patch("agent_bom.resolver.resolve_pypi_metadata", return_value=("2.32.3", "Apache-2.0")):
        assert await resolve_package_version(pkg, AsyncMock()) is True
    return package_version_provenance(pkg)


@pytest.mark.asyncio
async def test_unconstrained_setup_cfg_requirement_is_not_pinned(tmp_path):
    (tmp_path / "setup.cfg").write_text("[options]\ninstall_requires =\n    requests\n    idna==3.7\n")
    pkgs = {p.name: p for p in parse_setup_cfg(tmp_path / "setup.cfg")[0]}

    provenance = await _resolve_latest(pkgs["requests"])
    assert pkgs["requests"].version == "2.32.3"
    assert pkgs["requests"].resolved_from_registry is True
    assert provenance["version_source"] == "registry_latest"
    assert provenance["pinned"] is False
    assert "pinned_version" not in provenance
    assert provenance["floating_reference"] is True

    exact = package_version_provenance(pkgs["idna"])
    assert exact["pinned"] is True
    assert exact["pinned_version"] == "3.7"


@pytest.mark.asyncio
async def test_registry_fallback_for_unconstrained_requirement_is_not_pinned():
    pkg = Package(name="requests", version="unknown", ecosystem="pypi", registry_version="2.31.0")
    with patch("agent_bom.resolver.resolve_pypi_metadata", return_value=(None, None)):
        assert await resolve_package_version(pkg, AsyncMock()) is True
    provenance = package_version_provenance(pkg)
    assert pkg.version == "2.31.0"
    assert provenance["version_source"] == "registry_latest"
    assert provenance["pinned"] is False


@pytest.mark.asyncio
async def test_deduplicated_peers_inherit_unpinned_provenance():
    from agent_bom.resolver import resolve_all_versions

    first = Package(name="requests", version="unknown", ecosystem="pypi")
    second = Package(name="requests", version="unknown", ecosystem="pypi")
    with patch("agent_bom.resolver.resolve_pypi_metadata", return_value=("2.32.3", None)):
        await resolve_all_versions([first, second])
    for pkg in (first, second):
        assert pkg.version == "2.32.3"
        assert package_version_provenance(pkg)["pinned"] is False
