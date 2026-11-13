"""The post-release pin sweep moves real pins and leaves records of what was run alone.

``bump-version.py --published X`` rewrites every managed reference to X. A line
that records the version a check actually ran against (an upgrade rehearsal, a
review case's "how it was run") must keep that version, or the record becomes
false the moment the next release publishes.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / name
    mod_name = name.removesuffix(".py")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


OVERVIEW = """\
helm upgrade --install agent-bom oci://ghcr.io/koda-ai-studio/charts/agent-bom --version 0.114.0 \\

| Check | Command | Result |
|---|---|---|
| Upgrade 0.114.0 → this build, rollback | `upgrade.py --from-image agentbom/agent-bom:0.114.0` | Migration took 15 s |
"""

REVIEW_CASES_MD = """\
Run `uvx --from agent-bom==0.114.0 agent-bom scan -q`.

How the positive cases were run: with uvx --from agent-bom==0.114.0 and with this branch.
"""

REVIEW_CASES_JSON = {
    "cases": [
        {
            "prompt": "Run uvx --from agent-bom==0.114.0 agent-bom check",
            "how": "Exact commands from the skill, with uvx --from agent-bom==0.114.0 and with this branch.",
        }
    ]
}


def _tree(tmp_path: Path) -> dict[str, Path]:
    files = {
        "site-docs/deployment/overview.md": OVERVIEW,
        "docs/PLUGIN_REVIEW_CASES.md": REVIEW_CASES_MD,
        "integrations/codex/review-cases.json": json.dumps(REVIEW_CASES_JSON, indent=4) + "\n",
        "docs/PLUGIN_SUBMISSION.md": "# Submitting\n\nThe plugins pin agent-bom 0.114.0. Started from their lock files.\n",
    }
    paths = {}
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths[rel] = path
    return paths


def _patched_cva(tmp_path: Path, monkeypatch) -> ModuleType:
    cva = _load_script("check_version_alignment.py")
    monkeypatch.setattr(cva, "ROOT", tmp_path)
    monkeypatch.setattr(cva, "SCAN_ROOTS", (tmp_path / "docs", tmp_path / "site-docs", tmp_path / "integrations"))
    monkeypatch.setattr(cva, "LATEST_REQUIRED", ())
    monkeypatch.setattr(cva, "LAUNCHERS", ())
    monkeypatch.setattr(cva, "CHECKOUT_OVERRIDE", {})
    monkeypatch.setattr(cva, "_release_tags", set)
    return cva


def test_published_sweep_moves_real_pins_and_keeps_as_run_records(tmp_path, monkeypatch) -> None:
    paths = _tree(tmp_path)
    cva = _patched_cva(tmp_path, monkeypatch)

    cva.rewrite("0.115.0", published="0.115.0")

    overview = paths["site-docs/deployment/overview.md"].read_text()
    assert "--version 0.115.0" in overview
    assert "`upgrade.py --from-image agentbom/agent-bom:0.114.0`" in overview

    md = paths["docs/PLUGIN_REVIEW_CASES.md"].read_text()
    assert "Run `uvx --from agent-bom==0.115.0 agent-bom scan -q`." in md
    assert "How the positive cases were run: with uvx --from agent-bom==0.114.0" in md

    case = json.loads(paths["integrations/codex/review-cases.json"].read_text())["cases"][0]
    assert "agent-bom==0.115.0" in case["prompt"]
    assert "agent-bom==0.114.0" in case["how"]

    assert "The plugins pin agent-bom 0.115.0." in paths["docs/PLUGIN_SUBMISSION.md"].read_text()

    # The kept records are not drift for the checker either.
    assert cva.find_drift("0.115.0", published="0.115.0") == []


def test_plugin_submission_pin_line_is_drift_when_stale(tmp_path, monkeypatch) -> None:
    cva = _load_script("check_version_alignment.py")
    drift = cva.scan_text("docs/PLUGIN_SUBMISSION.md", "The plugins pin agent-bom 0.113.0. More.\n", "0.115.0", published="0.114.0")
    assert any("plugin submission pin" in line and "expected 0.114.0" in line for line in drift), drift


def test_an_as_run_record_outside_the_allowlist_is_still_swept() -> None:
    cva = _load_script("check_version_alignment.py")
    text = "How the positive cases were run: with uvx --from agent-bom==0.113.0.\n"
    assert cva.scan_text("docs/OTHER.md", text, "0.115.0", published="0.114.0")


def test_every_as_run_allowlist_entry_still_matches_a_managed_reference() -> None:
    """A renamed file or reworded line must not leave a dead entry behind."""
    cva = _load_script("check_version_alignment.py")
    for rel, line_pattern in cva.AS_RUN_EVIDENCE.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        lines = cva.as_run_lines(rel, text)
        assert lines, f"{rel}: no line matches {line_pattern.pattern!r}"
        managed_lines = {
            text.count("\n", 0, match.start(2)) + 1 for managed in cva.MANAGED_PATTERNS for match in managed.regex.finditer(text)
        }
        assert lines & managed_lines, f"{rel}: the as-run lines carry no managed version reference"
