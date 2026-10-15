"""Every suite that skips without a live Postgres must run in the Postgres CI job.

A suite gated on ``AGENT_BOM_POSTGRES_URL`` (or the job's admin DSN) is skipped
by every other lane, so leaving it out of the postgres-integration job means it
never executes anywhere. The scan is static (AST only) so it stays fast and does not
depend on which environment variables the test runner happens to have.
"""

from __future__ import annotations

import ast
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
POSTGRES_ENVS = frozenset({"AGENT_BOM_POSTGRES_URL", "AGENT_BOM_POSTGRES_ADMIN_URL"})
CONTRACT_STEP = "Run real Postgres storage contract"

# Live-Postgres suites deliberately kept out of the contract step. Each reason
# must be about the suite, not about a failure in the code under test.
EXCLUDED: dict[str, str] = {
    "tests/test_hub_bulk_ingest.py": "asserts a wall-clock throughput floor; shared runners measure below it",
}


def _suites(script: str) -> list[str]:
    return [token for token in script.replace("\\", " ").split() if token.startswith("tests/") and token.endswith(".py")]


def _job_steps() -> list[dict[str, str]]:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))["jobs"]["postgres-integration"]["steps"]


def _listed_suites() -> list[str]:
    return _suites(next(step["run"] for step in _job_steps() if step.get("name") == CONTRACT_STEP))


def _job_suites() -> set[str]:
    """Suites any step of the job runs (some need a dedicated database or env)."""
    return {suite for step in _job_steps() for suite in _suites(step.get("run", ""))}


def _mentions(node: ast.AST, names: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and child.value in POSTGRES_ENVS:
            return True
        if isinstance(child, ast.Name) and child.id in names:
            return True
    return False


def _is_skip_call(node: ast.AST, attr: str) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == attr


def _derived_names(tree: ast.Module) -> set[str]:
    """Names (module or local) whose value is read from the Postgres URL variable."""
    names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
            if not targets or not _mentions(node.value, names):  # type: ignore[arg-type]
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in names:
                    names.add(target.id)
                    changed = True
    return names


def _gated_scopes(tree: ast.Module, names: set[str]) -> list[ast.AST]:
    """Nodes whose skip depends on the Postgres URL: skipif marks and ``if ...: pytest.skip()``."""
    gated: list[ast.AST] = []
    for node in ast.walk(tree):
        if _is_skip_call(node, "skipif") and node.args and _mentions(node.args[0], names):  # type: ignore[attr-defined]
            gated.append(node)
        elif isinstance(node, ast.If) and _mentions(node.test, names):
            if any(_is_skip_call(child, "skip") for stmt in node.body for child in ast.walk(stmt)):
                gated.append(node)
    return gated


def _gated_fixtures(tree: ast.Module, names: set[str]) -> set[str]:
    fixtures: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_fixture = any("fixture" in ast.unparse(decorator) for decorator in node.decorator_list)
        if is_fixture and _gated_scopes(ast.Module(body=[node], type_ignores=[]), names):
            fixtures.add(node.name)
    return fixtures


def postgres_gated_suites(root: Path = ROOT) -> set[str]:
    """Return repo-relative test files that skip when the Postgres URL is unset."""
    parsed: dict[str, ast.Module] = {}
    for path in sorted((root / "tests").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if any(env in source for env in POSTGRES_ENVS):
            parsed[path.relative_to(root).as_posix()] = ast.parse(source)

    gated: set[str] = set()
    shared_fixtures: dict[str, set[str]] = {}
    for rel, tree in parsed.items():
        names = _derived_names(tree)
        if _gated_scopes(tree, names):
            gated.add(rel)
        shared_fixtures[rel[: -len(".py")].replace("/", ".")] = _gated_fixtures(tree, names)

    for path in sorted((root / "tests").rglob("test_*.py")):
        rel = path.relative_to(root).as_posix()
        if rel in gated:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module in shared_fixtures:
                if {alias.name for alias in node.names} & shared_fixtures[node.module]:
                    gated.add(rel)
    return {rel for rel in gated if Path(rel).name.startswith("test_")}


def test_every_postgres_gated_suite_runs_in_the_postgres_job() -> None:
    missing = sorted(postgres_gated_suites() - _job_suites() - set(EXCLUDED))
    assert not missing, f"add these live-Postgres suites to the '{CONTRACT_STEP}' step or to EXCLUDED with a reason: {missing}"


def test_postgres_job_list_and_exclusions_stay_honest() -> None:
    listed = _listed_suites()
    gated = postgres_gated_suites()
    assert len(listed) == len(set(listed)), "a suite is listed twice"
    assert not _job_suites() & set(EXCLUDED), "a suite cannot be both run and excluded"
    for suite in [*listed, *EXCLUDED]:
        assert (ROOT / suite).is_file(), suite
    assert set(EXCLUDED) <= gated, f"stale exclusions: {sorted(set(EXCLUDED) - gated)}"
    assert all(reason.strip() for reason in EXCLUDED.values())


def test_detector_recognizes_each_gating_pattern(tmp_path: Path) -> None:
    pg_url = "AGENT_BOM_POSTGRES_URL"
    tests = tmp_path / "tests"
    tests.mkdir()
    cases = {
        "test_mark.py": f'import os, pytest\npytestmark = pytest.mark.skipif(not os.environ.get("{pg_url}"), reason="x")\n',
        "test_alias.py": f'import os, pytest\n_DSN = os.environ.get("{pg_url}", "").strip()\n'
        "@pytest.mark.skipif(not _DSN, reason='x')\ndef test_a():\n    pass\n",
        "test_body.py": f'import os, pytest\ndef test_a():\n    if not os.getenv("{pg_url}"):\n        pytest.skip("x")\n',
        "test_fixture.py": f'import os, pytest\n@pytest.fixture\ndef pg():\n    dsn = os.environ.get("{pg_url}")\n'
        "    if not dsn:\n        pytest.skip('x')\n    yield dsn\n",
        "test_importer.py": "from tests.test_fixture import pg  # noqa: F401\ndef test_a(pg):\n    pass\n",
        "test_unrelated.py": f'import os\ndef test_a(monkeypatch):\n    monkeypatch.delenv("{pg_url}", raising=False)\n',
        "test_admin.py": 'import os, pytest\npytestmark = pytest.mark.skipif(not os.getenv("AGENT_BOM_POSTGRES_ADMIN_URL"), reason="x")\n',
        "test_other_gate.py": 'import os, pytest\npytestmark = pytest.mark.skipif(not os.environ.get("OTHER_URL"), reason="x")\n',
    }
    for name, source in cases.items():
        (tests / name).write_text(source, encoding="utf-8")

    assert postgres_gated_suites(tmp_path) == {
        f"tests/{name}"
        for name in ("test_mark.py", "test_alias.py", "test_body.py", "test_fixture.py", "test_importer.py", "test_admin.py")
    }
