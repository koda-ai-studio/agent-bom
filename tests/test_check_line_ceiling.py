"""The hard size ceiling: 1,000 lines per file, 150 per Python function, ratcheted."""

from __future__ import annotations

from pathlib import Path

from scripts import check_line_ceiling
from scripts.check_line_ceiling import (
    FILE_CEILING,
    FUNCTION_CEILING,
    ROOT,
    baseline_growth,
    check,
    current_ui_debt,
    load_ui_baseline,
    python_allowances,
    python_sizes,
    ui_sizes,
)


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return tmp_path


def _python_function(name: str, body_lines: int) -> str:
    return f"def {name}():\n" + "    pass\n" * body_lines


def test_current_tree_is_within_ceiling_or_recorded() -> None:
    errors = check(ROOT, python_allowances(ROOT), load_ui_baseline(ROOT), base_ui_counts=None)
    assert errors == [], "\n".join(errors)


def test_python_file_over_ceiling_fails_without_architecture_allowance(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"src/agent_bom/big.py": "x = 1\n" * (FILE_CEILING + 1)})
    sizes = python_sizes(root)
    assert sizes["big.py"] == FILE_CEILING + 1
    errors = check(root, {}, {}, base_ui_counts=None)
    assert errors == [f"src/agent_bom/big.py: {FILE_CEILING + 1} lines exceeds the {FILE_CEILING}-line file ceiling (allowance 0)"]
    assert not check(root, {"big.py": FILE_CEILING + 1}, {}, base_ui_counts=None)
    assert check(root, {"big.py": FILE_CEILING}, {}, base_ui_counts=None)


def test_python_function_over_ceiling_uses_qualified_name(tmp_path: Path) -> None:
    source = "class Worker:\n" + "\n".join("    " + line for line in _python_function("run", FUNCTION_CEILING).splitlines()) + "\n"
    root = _tree(tmp_path, {"src/agent_bom/api/worker.py": source})
    sizes = python_sizes(root)
    assert sizes["api/worker.py::Worker.run"] == FUNCTION_CEILING + 1
    errors = check(root, {}, {}, base_ui_counts=None)
    expected = f"{FUNCTION_CEILING + 1} lines exceeds the {FUNCTION_CEILING}-line function ceiling (allowance 0)"
    assert errors == [f"src/agent_bom/api/worker.py::Worker.run: {expected}"]
    assert not check(root, {"api/worker.py::Worker.run": FUNCTION_CEILING + 1}, {}, base_ui_counts=None)


def test_python_function_at_ceiling_passes(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"src/agent_bom/ok.py": _python_function("run", FUNCTION_CEILING - 1)})
    assert python_sizes(root)["ok.py::run"] == FUNCTION_CEILING
    assert not check(root, {}, {}, base_ui_counts=None)


def test_ui_file_over_ceiling_needs_a_matching_baseline_entry(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"ui/components/nav.tsx": "x\n" * (FILE_CEILING + 1), "ui/lib/small.ts": "x\n"})
    assert ui_sizes(root) == {"ui/components/nav.tsx": FILE_CEILING + 1, "ui/lib/small.ts": 1}
    assert check(root, {}, {}, base_ui_counts=None) == [
        f"ui/components/nav.tsx: {FILE_CEILING + 1} lines exceeds the {FILE_CEILING}-line file ceiling (allowance 0)"
    ]
    assert not check(root, {}, {"ui/components/nav.tsx": FILE_CEILING + 1}, base_ui_counts=None)
    assert check(root, {}, {"ui/components/nav.tsx": FILE_CEILING}, base_ui_counts=None)


def test_generated_and_vendored_ui_files_are_not_measured(tmp_path: Path) -> None:
    big = "x\n" * (FILE_CEILING + 1)
    root = _tree(
        tmp_path,
        {
            "ui/lib/api-schema.generated.ts": big,
            "ui/lib/vendor/sigma.min.js": big,
            "ui/node_modules/dep/index.js": big,
            "ui/__tests__/nav.test.tsx": big,
            "ui/hooks/use-thing.tsx": "x\n",
        },
    )
    assert ui_sizes(root) == {"ui/hooks/use-thing.tsx": 1}
    assert not check(root, {}, {}, base_ui_counts=None)


def test_stale_ui_baseline_entry_must_be_removed(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"ui/app/page.tsx": "x\n" * 10})
    errors = check(root, {}, {"ui/app/page.tsx": FILE_CEILING + 5, "ui/app/gone.tsx": FILE_CEILING + 1}, base_ui_counts=None)
    assert errors == [
        "ui/app/gone.tsx: baseline entry is stale (file within the ceiling or removed); run --write-baseline",
        "ui/app/page.tsx: baseline entry is stale (file within the ceiling or removed); run --write-baseline",
    ]


def test_editing_the_ui_baseline_cannot_approve_growth() -> None:
    base_counts = {"ui/components/nav.tsx": 1014}
    grown = baseline_growth({"ui/components/nav.tsx": 1015}, base_counts)
    assert grown == ["ui/components/nav.tsx: baseline allowance 1015 exceeds trusted 1014"]
    added = baseline_growth({"ui/components/new.tsx": 1001}, base_counts)
    assert added == ["ui/components/new.tsx: baseline allowance 1001 exceeds trusted 0"]
    assert not baseline_growth({"ui/components/nav.tsx": 1000}, base_counts)
    assert not baseline_growth({}, base_counts)


def test_check_applies_base_ref_ratchet(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"ui/components/nav.tsx": "x\n" * (FILE_CEILING + 2)})
    baseline = {"ui/components/nav.tsx": FILE_CEILING + 2}
    assert not check(root, {}, baseline, base_ui_counts={"ui/components/nav.tsx": FILE_CEILING + 2})
    assert check(root, {}, baseline, base_ui_counts={"ui/components/nav.tsx": FILE_CEILING + 1})
    assert check(root, {}, baseline, base_ui_counts={})


def test_write_baseline_records_only_current_ui_violators(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"ui/components/a.tsx": "x\n" * (FILE_CEILING + 1), "ui/components/b.tsx": "x\n" * FILE_CEILING})
    assert current_ui_debt(root) == {"ui/components/a.tsx": FILE_CEILING + 1}


def test_python_allowances_come_from_the_architecture_baseline() -> None:
    allowances = python_allowances(ROOT)
    assert all(value > 0 for value in allowances.values())
    assert any("::" in key for key in allowances)
    assert any("::" not in key for key in allowances)


def test_checked_in_ui_baseline_matches_the_tree() -> None:
    assert load_ui_baseline(ROOT) == current_ui_debt(ROOT)


def test_handwritten_api_contracts_are_not_exempt(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"ui/lib/api-types.ts": "export type Row = {};\n" * (FILE_CEILING + 1)})
    assert ui_sizes(root) == {"ui/lib/api-types.ts": FILE_CEILING + 1}
    assert check(root, {}, {}, base_ui_counts=None) == ["ui/lib/api-types.ts: 1001 lines exceeds the 1000-line file ceiling (allowance 0)"]


def test_write_cannot_reintroduce_debt_after_baseline_is_empty(tmp_path: Path, monkeypatch, capsys) -> None:
    baseline = '{"files": {}}\n'
    root = _tree(
        tmp_path,
        {
            "scripts/line_ceiling_baseline.json": baseline,
            "scripts/architecture-baseline.json": '{"debt": {}}\n',
            "ui/components/new.tsx": "x\n" * (FILE_CEILING + 1),
        },
    )
    monkeypatch.setattr(check_line_ceiling, "ROOT", root)
    monkeypatch.setattr("sys.argv", ["check_line_ceiling.py", "--write-baseline"])
    assert check_line_ceiling.main() == 1
    assert "baseline allowance 1001 exceeds trusted 0" in capsys.readouterr().out
    assert (root / check_line_ceiling.BASELINE).read_text() == baseline
