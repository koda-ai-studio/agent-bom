"""Modules with a pre-1.17 ``go`` directive list only direct requires in go.mod.

Before Go 1.17 the module graph was not pruned, so go.mod omits most transitive
modules; go.sum's module-zip (``h1:``) lines are the inventory of what was
built. From 1.17 on go.mod lists every module needed to build the main module
and stays the authority.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agent_bom.parsers.compiled_parsers import parse_go_packages

GO_SUM = textwrap.dedent("""\
    github.com/prometheus/client_golang v1.11.0 h1:aaaa=
    github.com/prometheus/client_golang v1.11.0/go.mod h1:bbbb=
    golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:cccc=
    golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 h1:dddd=
    golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e h1:eeee=
    golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e/go.mod h1:ffff=
    golang.org/x/net v0.0.0-20210525063256-abc453219eb5 h1:gggg=
    golang.org/x/sys v0.0.0-20210603081109-ebe580a85c40/go.mod h1:hhhh=
    github.com/old/mod v1.0.0 h1:iiii=
    github.com/new/mod v1.2.3 h1:jjjj=
""")


def _go_mod(directive: str) -> str:
    return textwrap.dedent(f"""\
        module github.com/prometheus/node_exporter

        {directive}

        require (
            github.com/prometheus/client_golang v1.11.0
            github.com/old/mod v1.0.0
        )

        replace github.com/old/mod => github.com/new/mod v1.2.3
    """)


def _inventory(tmp_path: Path, directive: str) -> dict[str, object]:
    (tmp_path / "go.mod").write_text(_go_mod(directive))
    (tmp_path / "go.sum").write_text(GO_SUM)
    return {p.name: p for p in parse_go_packages(tmp_path, verify_checksums=False)}


@pytest.mark.parametrize("directive", ["go 1.16", "go 1.12", ""])
def test_pre_117_modules_supplement_from_go_sum_zip_lines(tmp_path: Path, directive: str) -> None:
    packages = _inventory(tmp_path, directive)

    assert set(packages) == {
        "github.com/prometheus/client_golang",
        "github.com/new/mod",
        "golang.org/x/crypto",
        "golang.org/x/net",
    }
    crypto = packages["golang.org/x/crypto"]
    assert crypto.version == "0.0.0-20210616213533-5ff15b29337e"
    assert crypto.is_direct is False
    assert crypto.version_source == "lockfile"
    assert crypto.version_evidence[0]["source_file"].endswith("go.sum")
    assert packages["github.com/prometheus/client_golang"].is_direct is True
    assert packages["github.com/prometheus/client_golang"].version_source == "manifest"


@pytest.mark.parametrize("directive", ["go 1.17", "go 1.21", "go 1.22.3"])
def test_go_117_and_later_keep_go_mod_authoritative(tmp_path: Path, directive: str) -> None:
    packages = _inventory(tmp_path, directive)

    assert set(packages) == {"github.com/prometheus/client_golang", "github.com/new/mod"}
