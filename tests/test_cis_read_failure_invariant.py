"""CIS read failures can never produce PASS, and evidence never carries raw provider errors.

A per-resource read that fails for a reason other than a permission denial
(throttling, 5xx, malformed response) used to be counted neither as inspected
nor denied, so ``finalize_read_coverage`` returned PASS over a resource that was
never read. The AST guards keep every CIS module honest; the behavioural tests
drive one check per provider through a mixed read.
"""

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus
from agent_bom.cloud.cis_read_errors import READ_FAILED, read_error_label

_CLOUD = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "cloud"
_CIS_FILES = sorted(
    [
        *(_CLOUD / "aws_cis").glob("*.py"),
        *(_CLOUD / "azure_cis").glob("*.py"),
        *(_CLOUD / "gcp_cis").glob("*.py"),
        _CLOUD / "aws_cis_benchmark.py",
        _CLOUD / "azure_cis_benchmark.py",
        _CLOUD / "gcp_cis_benchmark.py",
    ]
)
_SECRET = "acct 123456789012 token=abc rate exceeded"


def _rel(path: Path) -> str:
    return str(path.relative_to(_CLOUD))


def _is_denied_test(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "is_access_denied_error"


def _recorder_target(call: ast.Call) -> str | None:
    """Name of the collection a call records into (``x.append`` / ``x.setdefault``) or the helper name."""
    if isinstance(call.func, ast.Name) and call.func.id == "record_read_failure":
        return "record_read_failure"
    if isinstance(call.func, ast.Attribute) and call.func.attr in {"append", "setdefault"}:
        base = call.func.value
        if isinstance(base, ast.Name):
            return base.id
    return None


def _records(nodes: list[ast.stmt]) -> set[str]:
    found: set[str] = set()
    for stmt in nodes:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call) and (target := _recorder_target(node)):
                found.add(target)
    return found


def _raises(nodes: list[ast.stmt]) -> bool:
    return any(isinstance(node, ast.Raise) for stmt in nodes for node in ast.walk(stmt))


def _non_denied_path(branch: ast.If, handler: ast.ExceptHandler) -> list[ast.stmt]:
    """Statements that run when the denied test is false: the else arm, or what follows the ``if``."""
    if branch.orelse:
        return branch.orelse
    for node in ast.walk(handler):
        for attr in ("body", "orelse"):
            block = getattr(node, attr, None)
            if isinstance(block, list) and branch in block:
                return block[block.index(branch) + 1 :]
    return []


def _unrecorded_denied_handlers() -> list[str]:
    offenders: list[str] = []
    for path in _CIS_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for handler in ast.walk(tree):
            if not isinstance(handler, ast.ExceptHandler):
                continue
            denied_ifs = [n for n in ast.walk(handler) if isinstance(n, ast.If) and _is_denied_test(n.test)]
            for branch in denied_ifs:
                denied_targets = _records(branch.body)
                if not denied_targets:
                    continue
                rest = _non_denied_path(branch, handler)
                if not (_records(rest) - denied_targets) and not _raises(rest):
                    offenders.append(f"{_rel(path)}:{branch.lineno}")
    return offenders


def _references(node: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def _bounded(expr: ast.expr, name: str) -> bool:
    """An f-string field derived from the exception is allowed only through a bounded label."""
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        if expr.func.id in {"read_error_label", "_check_failure_evidence"}:
            return True
        if expr.func.id == "sanitize_error":
            return any(k.arg == "generic" and isinstance(k.value, ast.Constant) and k.value.value is True for k in expr.keywords)
    if isinstance(expr, ast.Attribute) and expr.attr == "__name__":
        return True
    if isinstance(expr, ast.BoolOp):
        return all(_bounded(value, name) or not _references(value, name) for value in expr.values)
    return not _references(expr, name)


def _evidence_values(handler: ast.ExceptHandler) -> list[ast.expr]:
    values: list[ast.expr] = []
    for node in ast.walk(handler):
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Attribute) and t.attr == "evidence" for t in targets):
                values.append(node.value)
        elif isinstance(node, ast.keyword) and node.arg == "evidence":
            values.append(node.value)
    return values


def _raw_exception_evidence() -> list[str]:
    offenders: list[str] = []
    for path in _CIS_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for handler in ast.walk(tree):
            if not isinstance(handler, ast.ExceptHandler) or not handler.name:
                continue
            for value in _evidence_values(handler):
                fields = [n.value for n in ast.walk(value) if isinstance(n, ast.FormattedValue)]
                if any(not _bounded(field, handler.name) for field in fields):
                    offenders.append(f"{_rel(path)}:{value.lineno}")
    return offenders


def test_guard_scans_the_cis_packages() -> None:
    assert len(_CIS_FILES) > 30
    assert all(path.exists() for path in _CIS_FILES)


def test_every_denied_branch_also_records_non_denied_failures() -> None:
    assert _unrecorded_denied_handlers() == []


def test_cis_evidence_never_embeds_raw_exception_text() -> None:
    assert _raw_exception_evidence() == []


def test_read_error_label_keeps_type_and_code_but_never_message() -> None:
    exc = RuntimeError(_SECRET)
    exc.response = {"Error": {"Code": "Throttling", "Message": _SECRET}}  # type: ignore[attr-defined]
    assert read_error_label(exc) == "RuntimeError (Throttling)"
    assert read_error_label(ValueError(_SECRET)) == "ValueError"
    odd = RuntimeError(_SECRET)
    odd.code = "has spaces " + _SECRET  # type: ignore[attr-defined]
    assert read_error_label(odd) == "RuntimeError"
    denied = RuntimeError(f"AccessDenied for {_SECRET}")
    denied.response = {"Error": {"Code": "AccessDenied", "Message": _SECRET}}  # type: ignore[attr-defined]
    assert read_error_label(denied) == "permission denied: RuntimeError (AccessDenied)"


def _throttled() -> Exception:
    exc = RuntimeError(_SECRET)
    exc.response = {"Error": {"Code": "Throttling", "Message": _SECRET}}  # type: ignore[attr-defined]
    return exc


def _assert_error_without_secret(result) -> None:
    assert result.status == CheckStatus.ERROR, result.evidence
    assert "123456789012" not in result.evidence
    assert "token" not in result.evidence


class TestAwsMixedRead:
    def test_check_3_6_throttled_bucket_is_error_not_pass(self) -> None:
        from agent_bom.cloud.aws_cis_benchmark import _check_3_6

        cloudtrail = MagicMock()
        cloudtrail.describe_trails.return_value = {"trailList": [{"S3BucketName": "ok"}, {"S3BucketName": "slow"}]}
        s3 = MagicMock()

        def _logging(Bucket):  # noqa: N803 - botocore kwarg name
            if Bucket == "slow":
                raise _throttled()
            return {"LoggingEnabled": {"TargetBucket": "logs"}}

        s3.get_bucket_logging.side_effect = _logging
        result = _check_3_6(s3, cloudtrail)
        _assert_error_without_secret(result)
        assert f"{READ_FAILED}: 1" in result.evidence
        assert "slow" in result.resource_ids

    def test_check_3_6_known_failure_stays_fail(self) -> None:
        from agent_bom.cloud.aws_cis_benchmark import _check_3_6

        cloudtrail = MagicMock()
        cloudtrail.describe_trails.return_value = {"trailList": [{"S3BucketName": "bad"}, {"S3BucketName": "slow"}]}
        s3 = MagicMock()

        def _logging(Bucket):  # noqa: N803 - botocore kwarg name
            if Bucket == "slow":
                raise _throttled()
            return {}

        s3.get_bucket_logging.side_effect = _logging
        assert _check_3_6(s3, cloudtrail).status == CheckStatus.FAIL

    def test_check_2_1_2_unreadable_bucket_is_error_not_pass(self) -> None:
        from agent_bom.cloud.aws_cis_benchmark import _check_2_1_2

        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "ok"}, {"Name": "slow"}]}

        def _encryption(Bucket):  # noqa: N803 - botocore kwarg name
            if Bucket == "slow":
                raise _throttled()
            return {"ServerSideEncryptionConfiguration": {}}

        s3.get_bucket_encryption.side_effect = _encryption
        _assert_error_without_secret(_check_2_1_2(s3))


def _webapp(name: str) -> MagicMock:
    app = MagicMock()
    app.name = name
    app.id = f"/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Web/sites/{name}"
    return app


class TestAzureMixedRead:
    def test_check_9_1_failed_read_is_error_not_pass(self) -> None:
        from agent_bom.cloud.azure_cis_benchmark import _check_9_1

        web = MagicMock()
        web.web_apps.list.return_value = [_webapp("ok"), _webapp("slow")]

        def _auth(resource_group, name):
            if name == "slow":
                raise RuntimeError(_SECRET)
            return MagicMock(enabled=True)

        web.web_apps.get_auth_settings.side_effect = _auth
        result = _check_9_1(web)
        _assert_error_without_secret(result)
        assert "slow" in result.resource_ids

    def test_check_level_failure_evidence_is_bounded(self) -> None:
        from agent_bom.cloud.azure_cis_benchmark import _check_9_1

        web = MagicMock()
        web.web_apps.list.side_effect = RuntimeError(_SECRET)
        result = _check_9_1(web)
        _assert_error_without_secret(result)
        assert "RuntimeError" in result.evidence


def _install_gcp_storage(buckets: list) -> None:
    google_mod = sys.modules.get("google")
    if not (isinstance(google_mod, types.ModuleType) and getattr(google_mod, "__spec__", None) is None):
        google_mod = types.ModuleType("google")
        sys.modules["google"] = google_mod
    google_cloud = sys.modules.get("google.cloud")
    if not (isinstance(google_cloud, types.ModuleType) and getattr(google_cloud, "__spec__", None) is None):
        google_cloud = types.ModuleType("google.cloud")
        sys.modules["google.cloud"] = google_cloud
    google_mod.cloud = google_cloud  # type: ignore[attr-defined]
    storage_mod = types.ModuleType("google.cloud.storage")
    client = MagicMock()
    client.return_value.list_buckets.return_value = buckets
    storage_mod.Client = client  # type: ignore[attr-defined]
    google_cloud.storage = storage_mod  # type: ignore[attr-defined]
    sys.modules["google.cloud.storage"] = storage_mod


class TestGcpMixedRead:
    def test_check_5_1_failed_read_is_error_not_pass(self) -> None:
        from agent_bom.cloud.gcp_cis_benchmark import _check_5_1

        ok, slow = MagicMock(), MagicMock()
        ok.name, slow.name = "ok", "slow"
        policy = MagicMock()
        policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["user:a@example.com"]}]
        ok.get_iam_policy.return_value = policy
        slow.get_iam_policy.side_effect = RuntimeError(_SECRET)
        _install_gcp_storage([ok, slow])
        result = _check_5_1("my-project")
        _assert_error_without_secret(result)
        assert f"{READ_FAILED}: 1" in result.evidence

    @pytest.mark.parametrize("exc", [RuntimeError(_SECRET), ValueError(_SECRET)])
    def test_check_level_failure_evidence_is_bounded(self, exc: Exception) -> None:
        from agent_bom.cloud.gcp_cis._base import _check_failure_evidence

        evidence = _check_failure_evidence(exc)
        assert "123456789012" not in evidence
        assert type(exc).__name__ in evidence
