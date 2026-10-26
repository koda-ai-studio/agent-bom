"""go.mod replace directives and uv.lock local project rows."""

from __future__ import annotations

import textwrap

from agent_bom.parsers.compiled_parsers import _parse_go_mod_requires, parse_go_packages
from agent_bom.parsers.uv_lock import parse_uv_lock

GO_MOD = textwrap.dedent("""\
    module example.com/app

    go 1.22

    replace example.com/localdep => ../localdep

    require (
        example.com/localdep v0.0.0-00010101000000-000000000000
        github.com/old/mod v1.0.0
        github.com/single/mod v1.1.0
        golang.org/x/net v0.10.0
    )

    replace (
        github.com/old/mod => github.com/new/mod v1.2.3
        golang.org/x/net v0.10.0 => golang.org/x/net v0.23.0
    )

    replace github.com/single/mod v1.1.0 => github.com/fork/mod v1.1.1
""")


def test_replace_directives_do_not_span_lines(tmp_path):
    (tmp_path / "go.mod").write_text(GO_MOD)
    direct, _indirect, replace_map = _parse_go_mod_requires(tmp_path / "go.mod")

    assert "github.com/old/mod" in direct
    assert replace_map["github.com/old/mod"] == ("github.com/new/mod", "v1.2.3")
    assert replace_map["golang.org/x/net"] == ("golang.org/x/net", "v0.23.0")
    assert replace_map["github.com/single/mod"] == ("github.com/fork/mod", "v1.1.1")
    assert "(" not in replace_map


def test_replaced_modules_report_replacement_and_drop_local_paths(tmp_path):
    (tmp_path / "go.mod").write_text(GO_MOD)
    pkgs = {p.name: p.version for p in parse_go_packages(tmp_path)}

    assert pkgs == {"github.com/new/mod": "1.2.3", "github.com/fork/mod": "1.1.1", "golang.org/x/net": "0.23.0"}


UV_LOCK = textwrap.dedent("""\
    version = 1
    requires-python = ">=3.11"

    [[package]]
    name = "demo-app"
    version = "0.1.0"
    source = { editable = "." }
    dependencies = [{ name = "httpx" }]

    [[package]]
    name = "httpx"
    version = "0.27.0"
    source = { registry = "https://pypi.org/simple" }
""")


def test_uv_lock_root_project_is_not_a_dependency(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo-app"\nversion = "0.1.0"\ndependencies = ["httpx>=0.27"]\n')
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    assert [p.name for p in parse_uv_lock(tmp_path)] == ["httpx"]
    (tmp_path / "uv.lock").write_text(UV_LOCK.replace('{ editable = "." }', '{ virtual = "." }'))
    assert [p.name for p in parse_uv_lock(tmp_path)] == ["httpx"]
