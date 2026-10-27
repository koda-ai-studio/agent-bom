"""Guards for the per-test and per-module seeded demo clients."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from tests import _demo_estate_fixtures as fixtures

_TESTS = Path(__file__).resolve().parent
_WRITES = {"post", "put", "patch", "delete", "save_graph", "maybe_bootstrap_demo_estate", "refresh_demo_daily_evidence"}


def _test_functions(path: Path) -> list[ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]


def _arguments(node: ast.FunctionDef) -> set[str]:
    return {arg.arg for arg in node.args.args}


def _shared_modules() -> list[Path]:
    return sorted(
        path for path in _TESTS.rglob("test_*.py") if any("shared_demo_estate_client" in _arguments(node) for node in _test_functions(path))
    )


def test_a_second_seed_in_one_process_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(fixtures, "_active_seeds", [tmp_path / "live"])

    with pytest.raises(RuntimeError, match="one demo client kind per module"):
        with fixtures.seeded_demo_estate(monkeypatch, tmp_path):
            pass


def test_shared_seed_modules_exist() -> None:
    assert _shared_modules(), "no module uses shared_demo_estate_client"


@pytest.mark.parametrize("path", _shared_modules(), ids=lambda path: path.name)
def test_shared_seed_modules_only_read(path: Path) -> None:
    """A module on the shared seed never mixes in per-test seeds, patches, or writes."""
    problems: list[str] = []
    for node in _test_functions(path):
        arguments = _arguments(node)
        if "demo_estate_client" in arguments:
            problems.append(f"{node.name} mixes the per-test seed into a shared-seed module")
        if "shared_demo_estate_client" not in arguments:
            continue
        if "monkeypatch" in arguments:
            problems.append(f"{node.name} patches process state under a shared seed")
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
                if name in _WRITES or name.startswith("seed_"):
                    problems.append(f"{node.name} calls {name}() under a shared seed")
    assert not problems, "\n".join(problems)


_ISO_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
_EQUIVALENCE_READS = (
    ("/v1/jobs", {}),
    ("/v1/findings", {"limit": 25}),
    ("/v1/posture/counts", {}),
    ("/v1/posture", {}),
    ("/v1/trends", {"limit": 30}),
    ("/v1/overview", {}),
    ("/v1/compliance", {}),
    ("/v1/agents", {}),
    ("/v1/graph", {"limit": 50}),
    ("/v1/demo-estate/status", {}),
    ("/v1/gateway/feed", {}),
    ("/v1/gateway/feed/kpis", {}),
    ("/v1/runtime/production-index", {}),
)


def _reads(client: TestClient) -> dict[str, tuple[int, str]]:
    # Gateway events are synthesized relative to boot time on every boot, so
    # instants are masked; ids, counts, and every other field must match.
    return {
        path: (response.status_code, _ISO_TIMESTAMP.sub("<ts>", response.text))
        for path, params in _EQUIVALENCE_READS
        for response in [client.get(path, headers=fixtures.VIEWER, params=params)]
    }


def _direct_seed_callers() -> list[str]:
    callers = []
    for path in sorted(_TESTS.rglob("test_*.py")):
        if path == Path(__file__).resolve():
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name == "seeded_demo_estate":
                    callers.append(f"{path.relative_to(_TESTS).as_posix()}:{node.lineno}")
    return callers


def test_per_test_clients_boot_on_the_seeded_template(
    _demo_estate_template: fixtures.DemoEstateTemplate, demo_estate_client: TestClient
) -> None:
    """The per-test client copies the worker's seed instead of reseeding."""
    from agent_bom.demo_estate.bootstrap import get_demo_estate_bootstrap_status

    status = get_demo_estate_bootstrap_status()
    days = _demo_estate_template.seeded_days
    assert days and len(days) == len(set(days)), f"the worker seeded more than once a day: {days}"
    assert status.get("graph_seeded") is False, status
    assert status.get("reason") == "demo_jobs_present", status
    assert demo_estate_client.get("/v1/findings", headers=fixtures.VIEWER, params={"limit": 1}).json()["total"] > 0


def test_no_test_module_seeds_the_demo_estate_itself() -> None:
    """A fresh seed costs about a minute; demo tests take a client fixture, which copies the template."""
    assert not _direct_seed_callers(), _direct_seed_callers()


def test_a_copied_seed_serves_the_same_estate_as_the_seed_it_copies(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Booting on a database copy takes the restart path and serves identical reads."""
    seed_dir, copy_dir = tmp_path / "seed", tmp_path / "copy"
    seed_dir.mkdir()
    with fixtures.seeded_demo_estate(monkeypatch, seed_dir) as client:
        seeded = _reads(client)
    fixtures.copy_demo_databases(seed_dir, copy_dir)
    with fixtures.seeded_demo_estate(monkeypatch, copy_dir) as client:
        copied = _reads(client)

    assert all(status == 200 for status, _ in seeded.values()), {path: status for path, (status, _) in seeded.items()}
    mismatched = sorted(path for path in seeded if seeded[path] != copied[path])
    assert not mismatched, mismatched
