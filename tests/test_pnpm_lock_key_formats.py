"""pnpm-lock.yaml package keys parse to the exact (name, version) for every lockfile format."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.parsers.node_parsers import parse_pnpm_lock
from agent_bom.parsers.pnpm_keys import parse_pnpm_key, pnpm_dependency_ref

V5_CASES = [
    ("/vite/4.0.0", ("vite", "4.0.0")),
    ("/@vue/server-renderer/3.2.45_vue@3.2.45", ("@vue/server-renderer", "3.2.45")),
    ("/postcss-js/4.0.0_postcss@8.4.19", ("postcss-js", "4.0.0")),
    ("/@vitejs/plugin-vue/4.0.0_vite@4.0.0+vue@3.2.45", ("@vitejs/plugin-vue", "4.0.0")),
    ("/ts-node/10.9.1_@types+node@18.11.18+typescript@4.9.4", ("ts-node", "10.9.1")),
    ("/react-dom/18.2.0-rc.1_react@18.2.0", ("react-dom", "18.2.0-rc.1")),
    ("/semver/7.3.8", ("semver", "7.3.8")),
]

V6_CASES = [
    ("/vite@4.0.0", ("vite", "4.0.0")),
    ("/@vue/server-renderer@3.3.4(vue@3.3.4)", ("@vue/server-renderer", "3.3.4")),
    ("/postcss-js@4.0.1(postcss@8.4.31)", ("postcss-js", "4.0.1")),
    ("/@vitejs/plugin-vue@4.4.0(vite@4.5.0)(vue@3.3.4)", ("@vitejs/plugin-vue", "4.4.0")),
    ("/ts-node@10.9.1(@types/node@20.8.0)(typescript@5.2.2)", ("ts-node", "10.9.1")),
]

V9_CASES = [
    ("vite@5.0.0", ("vite", "5.0.0")),
    ("@vue/server-renderer@3.4.0(vue@3.4.0)", ("@vue/server-renderer", "3.4.0")),
    ("postcss-js@4.0.1(postcss@8.4.31)", ("postcss-js", "4.0.1")),
    ("@babel/core@7.23.0", ("@babel/core", "7.23.0")),
]


@pytest.mark.parametrize(("key", "expected"), V5_CASES)
def test_v5_keys(key: str, expected: tuple[str, str]) -> None:
    assert parse_pnpm_key(key, 5.4) == expected


@pytest.mark.parametrize(("key", "expected"), V6_CASES)
def test_v6_keys(key: str, expected: tuple[str, str]) -> None:
    assert parse_pnpm_key(key, 6.0) == expected


@pytest.mark.parametrize(("key", "expected"), V9_CASES)
def test_v9_keys(key: str, expected: tuple[str, str]) -> None:
    assert parse_pnpm_key(key, 9.0) == expected


@pytest.mark.parametrize("key", ["/github.com/user/repo/0123abcd", "registry.example.com/foo/-/foo-1.0.0.tgz", "", "/"])
def test_non_registry_keys_are_not_misparsed(key: str) -> None:
    assert parse_pnpm_key(key, 5.4) is None


@pytest.mark.parametrize(
    ("value", "lockfile_version", "expected"),
    [
        ("3.2.45_vue@3.2.45", 5.4, "3.2.45"),
        ("4.0.0", 5.4, "4.0.0"),
        ("3.3.4(vue@3.3.4)", 6.0, "3.3.4"),
        ("3.4.0(vue@3.4.0)", 9.0, "3.4.0"),
        ("link:../pkg", 9.0, None),
        ({"specifier": "^3.4.0", "version": "3.4.0(vue@3.4.0)"}, 9.0, "3.4.0"),
    ],
)
def test_dependency_version_refs(value: object, lockfile_version: float, expected: str | None) -> None:
    ref = pnpm_dependency_ref("dep", value, lockfile_version)
    assert (ref[1] if ref else None) == expected
    if ref:
        assert ref[0] == "dep"


@pytest.mark.parametrize(
    ("value", "lockfile_version"),
    [("/string-width/4.2.3", 5.4), ("/string-width@4.2.3", 6.0), ("string-width@4.2.3", 9.0)],
)
def test_alias_dependency_refs_resolve_to_target(value: str, lockfile_version: float) -> None:
    assert pnpm_dependency_ref("string-width-cjs", value, lockfile_version) == ("string-width", "4.2.3")


V5_LOCK = """\
lockfileVersion: 5.4

importers:
  .:
    specifiers:
      '@vue/server-renderer': ^3.2.45
      postcss-js: ^4.0.0
    dependencies:
      '@vue/server-renderer': 3.2.45_vue@3.2.45
      postcss-js: 4.0.0_postcss@8.4.19

packages:

  /@vue/server-renderer/3.2.45_vue@3.2.45:
    resolution: {integrity: sha512-x}
    dependencies:
      vue: 3.2.45
    dev: false

  /postcss-js/4.0.0_postcss@8.4.19:
    resolution: {integrity: sha512-y}
    dependencies:
      postcss: 8.4.19
    dev: false

  /postcss/8.4.19:
    resolution: {integrity: sha512-z}
    dev: false

  /vue/3.2.45:
    resolution: {integrity: sha512-w}
    dev: false
"""


def test_v5_lockfile_inventory_and_topology(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_text(V5_LOCK)
    packages = {(p.name, p.version): p for p in parse_pnpm_lock(tmp_path)}
    assert set(packages) == {
        ("@vue/server-renderer", "3.2.45"),
        ("postcss-js", "4.0.0"),
        ("postcss", "8.4.19"),
        ("vue", "3.2.45"),
    }
    assert all("/" not in name.lstrip("@").split("/", 1)[-1] for name, _ in packages)
    assert packages[("postcss-js", "4.0.0")].is_direct is True
    assert packages[("postcss", "8.4.19")].is_direct is False


V9_LOCK = """\
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      '@vue/server-renderer':
        specifier: ^3.4.0
        version: 3.4.0(vue@3.4.0)

packages:
  '@vue/server-renderer@3.4.0':
    resolution: {integrity: sha512-x}
  vue@3.4.0:
    resolution: {integrity: sha512-w}

snapshots:
  '@vue/server-renderer@3.4.0(vue@3.4.0)':
    dependencies:
      vue: 3.4.0
  vue@3.4.0: {}
"""


def test_v9_lockfile_inventory_and_topology(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_text(V9_LOCK)
    packages = {(p.name, p.version): p for p in parse_pnpm_lock(tmp_path)}
    assert set(packages) == {("@vue/server-renderer", "3.4.0"), ("vue", "3.4.0")}
    assert packages[("@vue/server-renderer", "3.4.0")].is_direct is True
    assert packages[("vue", "3.4.0")].is_direct is False
