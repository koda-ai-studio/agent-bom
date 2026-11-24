"""The findings fold decodes and projects a committed job once per row version."""

from __future__ import annotations

import ast
import time
from pathlib import Path

import pytest

from agent_bom.api import finding_fold_jobs
from agent_bom.api.finding_fold_jobs import FOLD_RESULT_KEYS, fold_jobs
from tests.api.test_scan_job_sla_history import get_rows, job
from tests.api.versioned_job_store import VersionedInMemoryJobStore

_SRC = Path(__file__).resolve().parents[2] / "src" / "agent_bom"
# Every module whose functions the fold calls with a job: their result reads must survive the trim.
_FOLD_MODULES = ("api/finding_job_metadata.py", "api/findings_current.py", "evidence/push_scope.py")


@pytest.fixture
def versioned(monkeypatch):
    from agent_bom.api import stores
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env

    monkeypatch.setattr("agent_bom.api.campaign_reconciliation.poll_campaign_reconciliation", lambda: None)
    finding_fold_jobs.clear()
    original = stores._store
    store = VersionedInMemoryJobStore()
    stores.set_job_store(store)
    set_compliance_hub_store(InMemoryComplianceHubStore())
    enable_trusted_proxy_env()
    yield store
    stores.set_job_store(original)
    set_compliance_hub_store(None)
    disable_trusted_proxy_env()
    finding_fold_jobs.clear()


def test_a_new_scan_decodes_only_that_scan(versioned):
    versioned.put(job(8))
    versioned.put(job(9, target="repo-b"))
    assert len(get_rows()) == 2
    assert sorted(versioned.loaded[-1]) == ["history-tenant-repo-a-8", "history-tenant-repo-b-9"]

    versioned.put(job(10, target="repo-c"))
    assert len(get_rows()) == 3
    assert versioned.loaded[-1] == ["history-tenant-repo-c-10"]


def test_a_rewritten_job_is_decoded_again(versioned):
    original = job(8)
    versioned.put(original)
    assert get_rows()[0]["severity"] == "critical"
    rewritten = job(8)
    rewritten.result["findings"][0]["severity"] = "low"
    versioned.put(rewritten)
    assert get_rows()[0]["severity"] == "low"
    assert versioned.loaded[-1] == ["history-tenant-repo-a-8"]


def test_changed_row_inputs_or_a_passed_horizon_reproject(versioned):
    versioned.put(job(8))
    calls: list[str] = []

    def project(scan):
        calls.append(scan.job_id)
        return []

    fold_jobs("history-tenant", versioned, (("a",), None), project)
    fold_jobs("history-tenant", versioned, (("a",), None), project)
    assert calls == ["history-tenant-repo-a-8"]
    fold_jobs("history-tenant", versioned, (("b",), None), project)
    assert len(calls) == 2
    expired = time.time() - 1
    fold_jobs("history-tenant", versioned, (("c",), expired), project)
    fold_jobs("history-tenant", versioned, (("c",), expired), project)
    assert len(calls) == 4


def test_digest_keeps_only_the_result_keys_the_fold_reads(versioned):
    scan = job(8)
    scan.result["agents"] = [{"name": "heavy"}]
    versioned.put(scan)
    jobs, rows_for = fold_jobs("history-tenant", versioned, (("a",), None), lambda _scan: [{"id": "x"}])
    assert set(jobs[0].result) <= FOLD_RESULT_KEYS
    assert "agents" not in jobs[0].result and jobs[0].result["findings"]
    assert rows_for(jobs[0]) == [{"id": "x"}]


def test_stores_without_row_versions_and_opt_out_decode_in_full(versioned, monkeypatch):
    from agent_bom.api.store import InMemoryJobStore

    assert fold_jobs("history-tenant", InMemoryJobStore(), (("a",), None), lambda _scan: []) is None
    monkeypatch.setenv("AGENT_BOM_FINDING_WALK_CACHE", "0")
    assert fold_jobs("history-tenant", versioned, (("a",), None), lambda _scan: []) is None


def _literal_strings(node: ast.AST) -> set[str]:
    return {item.value for item in ast.walk(node) if isinstance(item, ast.Constant) and isinstance(item.value, str)}


def _result_keys(tree: ast.AST) -> set[str]:
    """String keys read from a job result: ``result.get("k")``, ``result["k"]``, and keys looped over a literal tuple."""

    def on_result(node: ast.AST) -> bool:
        return any(
            (isinstance(item, ast.Name) and item.id in {"result", "raw_result"})
            or (isinstance(item, ast.Attribute) and item.attr == "result")
            for item in ast.walk(node)
        )

    loops: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.For | ast.comprehension) and isinstance(node.target, ast.Name):
            loops.setdefault(node.target.id, set()).update(_literal_strings(node.iter))
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
            if on_result(node.func.value):
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    keys.add(arg.value)
                elif isinstance(arg, ast.Name):
                    assert arg.id in loops, f"unresolvable result key {arg.id}"
                    keys |= loops[arg.id]
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            if on_result(node.value):
                keys.add(node.slice.value)
    return keys


def test_every_result_key_the_fold_reads_survives_the_trim():
    read = set().union(*(_result_keys(ast.parse((_SRC / module).read_text())) for module in _FOLD_MODULES))
    assert {"scan_run", "findings", "pushed", "dry_run"} <= read
    assert read <= FOLD_RESULT_KEYS, sorted(read - FOLD_RESULT_KEYS)
