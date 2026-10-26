"""Workspace members owned by an ancestor lockfile are not re-parsed as declarations."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from agent_bom.parsers.node_lockfiles import has_node_lock
from agent_bom.parsers.node_parsers import parse_npm_packages, parse_pnpm_lock

PNPM_LOCK = textwrap.dedent("""\
    lockfileVersion: '9.0'

    importers:

      .:
        devDependencies:
          typescript:
            specifier: ^5.4.0
            version: 5.4.5

      packages/client:
        dependencies:
          '@temporalio/common':
            specifier: workspace:*
            version: link:../common
          long:
            specifier: ^5.2.3
            version: 5.2.3

      'packages/common':
        dependencies:
          ms:
            specifier: ^3.0.0-canary.1
            version: 3.0.0-canary.1

    packages:

      long@5.2.3:
        resolution: {integrity: sha512-abc}

      ms@3.0.0-canary.1:
        resolution: {integrity: sha512-def}

      typescript@5.4.5:
        resolution: {integrity: sha512-ghi}
""")


def _member(root: Path, rel: str, deps: dict[str, str]) -> Path:
    member = root / rel
    member.mkdir(parents=True)
    (member / "package.json").write_text(json.dumps({"name": f"@temporalio/{member.name}", "version": "1.11.0", "dependencies": deps}))
    return member


def _pnpm_workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    (tmp_path / "pnpm-workspace.yaml").write_text("packages:\n  - packages/*\n")
    (tmp_path / "package.json").write_text('{"name": "root", "private": true}')
    (tmp_path / "pnpm-lock.yaml").write_text(PNPM_LOCK)
    client = _member(tmp_path, "packages/client", {"@temporalio/common": "workspace:*", "long": "^5.2.3"})
    common = _member(tmp_path, "packages/common", {"ms": "^3.0.0-canary.1"})
    stray = _member(tmp_path, "examples/stray", {"left-pad": "1.3.0"})
    return client, common, stray


def test_pnpm_importer_members_are_locked(tmp_path):
    client, common, stray = _pnpm_workspace(tmp_path)

    assert has_node_lock(client)
    assert has_node_lock(common)
    assert not has_node_lock(stray)


def test_pnpm_members_emit_no_declaration_only_packages(tmp_path):
    client, common, stray = _pnpm_workspace(tmp_path)

    assert parse_npm_packages(client) == []
    assert parse_npm_packages(common) == []
    assert [p.name for p in parse_npm_packages(stray)] == ["left-pad"]


def test_root_pnpm_lock_never_reports_first_party_workspace_links(tmp_path):
    _pnpm_workspace(tmp_path)
    names = {p.name for p in parse_pnpm_lock(tmp_path)}
    assert names == {"long", "ms", "typescript"}


def test_package_lock_workspace_member_is_locked(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "root", "workspaces": ["packages/*"]}')
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "workspaces": ["packages/*"]},
                    "packages/api": {"name": "@acme/api", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}},
                    "node_modules/express": {"version": "4.19.2"},
                    "node_modules/@acme/api": {"resolved": "packages/api", "link": True},
                },
            }
        )
    )
    api = _member(tmp_path, "packages/api", {"express": "^4.18.0"})
    assert has_node_lock(api)
    assert parse_npm_packages(api) == []


def test_yarn_workspace_member_is_locked(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "root", "private": true, "workspaces": ["packages/*"]}')
    (tmp_path / "yarn.lock").write_text('express@^4.18.0:\n  version "4.19.2"\n')
    api = _member(tmp_path, "packages/api", {"express": "^4.18.0"})
    outside = _member(tmp_path, "tools/script", {"chalk": "5.3.0"})
    assert has_node_lock(api)
    assert not has_node_lock(outside)
