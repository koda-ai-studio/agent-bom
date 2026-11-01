"""First-party npm workspace members are inventory context, never registry dependencies.

A ``package-lock.json`` with ``workspaces`` lists each member twice: once at
its directory path (``server``) and once as a ``node_modules/server`` symlink
with ``link: true`` and no version. Emitting either as a package turned a
monorepo's own ``server`` into ``server@unknown`` (then registry-resolved to a
stranger's ``server@1.0.42``) and a CRITICAL "typosquat of semver".
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.malicious import check_typosquat
from agent_bom.models import Package
from agent_bom.parsers.node_parsers import parse_npm_packages
from agent_bom.scanners.package_coverage import _flag_suspicious_packages


def _workspace_lock(root: Path) -> None:
    (root / "package.json").write_text(json.dumps({"name": "demo", "private": True, "workspaces": ["server", "web"]}))
    for member in ("server", "web"):
        (root / member).mkdir()
        (root / member / "package.json").write_text(json.dumps({"name": member, "private": True, "version": "0.1.0"}))
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "workspaces": ["server", "web"], "devDependencies": {"concurrently": "10.0.3"}},
                    "node_modules/concurrently": {"version": "10.0.3"},
                    "node_modules/express": {"version": "5.2.1"},
                    "node_modules/server": {"resolved": "server", "link": True},
                    "node_modules/web": {"resolved": "web", "link": True},
                    "server": {"version": "0.1.0", "dependencies": {"express": "5.2.1"}},
                    "web": {"version": "0.1.0"},
                },
            }
        )
    )


def test_lockfile_workspace_members_and_links_are_not_packages(tmp_path: Path) -> None:
    _workspace_lock(tmp_path)

    packages = parse_npm_packages(tmp_path)

    by_name = {p.name: p for p in packages}
    assert set(by_name) == {"concurrently", "express"}
    assert not [p for p in packages if p.version == "unknown"]
    # The member's dependency edge survives even though the member itself is not a package.
    assert by_name["express"].parent_package == "server"


def test_first_party_workspace_dependency_is_never_typosquat_checked() -> None:
    first_party = Package(name="server", version="0.1.0", ecosystem="npm", reachability_evidence="workspace_manifest")
    first_party.version_source = "workspace"
    squat = Package(name="expresss", version="1.0.0", ecosystem="npm")

    _flag_suspicious_packages([first_party, squat])

    assert first_party.is_malicious is False
    assert squat.is_malicious is True
    assert "express" in (squat.malicious_reason or "")


def test_generic_first_party_names_are_not_squats_of_semver() -> None:
    for name in ("server", "client", "web", "app"):
        assert check_typosquat(name, "npm") is None, name


def test_real_lookalikes_are_still_squats() -> None:
    assert check_typosquat("expresss", "npm") == "express"
    assert check_typosquat("typescirpt", "npm") == "typescript"
    assert check_typosquat("reqeusts", "pypi") == "requests"
