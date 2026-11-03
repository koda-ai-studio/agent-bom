"""Modules with a pre-1.17 ``go`` directive list only direct requires in go.mod.

Before Go 1.17 the module graph was not pruned, so go.mod omits most transitive
modules. The build list (``go list -m all``) selects, for every module path in
the graph, the highest version go.sum records; modules recorded only by
``/go.mod`` lines are in the graph but contribute no code to the build and are
marked so. From 1.17 on go.mod lists every module needed to build the main
module and stays the authority.
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
    golang.org/x/net v0.0.0-20210525063256-abc453219eb5/go.mod h1:gggh=
    golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2/go.mod h1:gggi=
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
def test_pre_117_inventory_is_the_build_list(tmp_path: Path, directive: str) -> None:
    packages = _inventory(tmp_path, directive)

    assert {f"{name}@{pkg.version}" for name, pkg in packages.items()} == {
        "github.com/prometheus/client_golang@1.11.0",
        "github.com/new/mod@1.2.3",
        "golang.org/x/crypto@0.0.0-20210616213533-5ff15b29337e",
        "golang.org/x/net@0.0.0-20211112202133-69e39bad7dc2",
        "golang.org/x/sys@0.0.0-20210603081109-ebe580a85c40",
    }
    crypto = packages["golang.org/x/crypto"]
    assert crypto.is_direct is False
    assert crypto.version_source == "lockfile"
    assert crypto.reachability_evidence == "lockfile"
    assert crypto.version_evidence[0]["source_file"].endswith("go.sum")
    assert crypto.version_evidence[0]["build_list_role"] == "module_zip"
    assert packages["github.com/prometheus/client_golang"].is_direct is True
    assert packages["github.com/prometheus/client_golang"].version_source == "manifest"


@pytest.mark.parametrize("name", ["golang.org/x/sys", "golang.org/x/net"])
def test_pre_117_graph_only_modules_are_marked_no_code_in_build(tmp_path: Path, name: str) -> None:
    pkg = _inventory(tmp_path, "go 1.16")[name]

    assert pkg.reachability_evidence == "declaration_only"
    assert pkg.version_confidence == "high"
    assert pkg.version_evidence[0]["build_list_role"] == "module_graph_only"
    assert "no code in build" in pkg.version_evidence[0]["parser"]


def test_pre_117_go_mod_requirement_is_raised_to_the_selected_version(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/m\n\ngo 1.14\n\nrequire golang.org/x/text v0.3.0\n")
    (tmp_path / "go.sum").write_text(
        "golang.org/x/text v0.3.0/go.mod h1:aaaa=\ngolang.org/x/text v0.3.6 h1:bbbb=\ngolang.org/x/text v0.3.6/go.mod h1:cccc=\n"
    )
    (pkg,) = parse_go_packages(tmp_path, verify_checksums=False)

    assert (pkg.name, pkg.version, pkg.is_direct) == ("golang.org/x/text", "0.3.6", True)
    assert pkg.declared_version == "0.3.0"
    assert pkg.version_conflicts == [{"source": "go.mod require", "version": "0.3.0", "selected_by": "go.sum build list"}]


def test_pre_117_replacement_target_keeps_its_pinned_version(tmp_path: Path) -> None:
    packages = _inventory(tmp_path, "go 1.16")

    assert "github.com/old/mod" not in packages
    assert packages["github.com/new/mod"].version == "1.2.3"


def test_go_117_requirement_is_not_raised(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/m\n\ngo 1.17\n\nrequire golang.org/x/text v0.3.0\n")
    (tmp_path / "go.sum").write_text("golang.org/x/text v0.3.6 h1:bbbb=\n")
    (pkg,) = parse_go_packages(tmp_path, verify_checksums=False)

    assert pkg.version == "0.3.0"


@pytest.mark.parametrize("directive", ["go 1.17", "go 1.21", "go 1.22.3"])
def test_go_117_and_later_keep_go_mod_authoritative(tmp_path: Path, directive: str) -> None:
    packages = _inventory(tmp_path, directive)

    assert set(packages) == {"github.com/prometheus/client_golang", "github.com/new/mod"}
