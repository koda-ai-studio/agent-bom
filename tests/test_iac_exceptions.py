"""IaC exceptions: ignore-file entries, inline markers, expiry, and retained evidence."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from agent_bom.iac import scan_iac_with_context
from agent_bom.iac.exceptions import IaCException, ResourceSelector, is_iac_ignore_entry, parse_ignore_entries
from agent_bom.iac.models import ScanContext, iac_findings_payload

POD = """apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    env: {env}
spec:
  containers:
    - name: app
      image: nginx:1.25@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      securityContext:
{marker}        privileged: true
"""

TODAY = date(2026, 11, 2)


def _pod(root: Path, rel: str = "k8s/pod.yaml", *, name: str = "debug", namespace: str = "dev", env: str = "dev", marker: str = "") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(POD.format(name=name, namespace=namespace, env=env, marker=marker))
    return root


def _scan(root: Path, entries: list[dict] | None = None, today: date = TODAY):
    exceptions = parse_ignore_entries(entries or [], origin=".agent-bom-ignore.yaml")
    return scan_iac_with_context(root, ScanContext(exceptions=tuple(exceptions), today=today))


def _rules(findings) -> list[str]:
    return sorted(f.rule_id for f in findings)


# ── ignore-file entries ─────────────────────────────────────────────────────


def test_rule_and_path_entry_suppresses_and_retains_the_finding(tmp_path: Path) -> None:
    root = _pod(tmp_path)
    result = _scan(
        root, [{"rule": "K8S-001", "path": "k8s/*.yaml", "reason": "debug pod, dev only", "owner": "platform", "expires": "2026-12-31"}]
    )
    assert "K8S-001" not in _rules(result.findings)
    assert _rules(result.suppressed) == ["K8S-001"]
    record = result.suppressed[0].suppression
    assert record is not None
    assert record["state"] == "accepted_risk"
    assert record["source"] == "ignore_file"
    assert record["reason"] == "debug pod, dev only"
    assert record["owner"] == "platform"
    assert record["expires"] == "2026-12-31"
    assert record["origin"].startswith(".agent-bom-ignore.yaml")
    assert record["exception_id"]


def test_id_and_type_iac_entries_are_recognized(tmp_path: Path) -> None:
    root = _pod(tmp_path)
    assert is_iac_ignore_entry({"id": "K8S-001", "reason": "x"})
    assert is_iac_ignore_entry({"type": "iac", "rule": "K8S-001", "reason": "x"})
    assert not is_iac_ignore_entry({"id": "CVE-2024-1234", "reason": "x"})
    assert not is_iac_ignore_entry({"id": "GHSA-aaaa-bbbb-cccc", "reason": "x"})
    result = _scan(
        root, [{"id": "K8S-001", "reason": "accepted"}, {"type": "iac", "id": "K8S-006", "path": "k8s/**", "reason": "ro fs n/a"}]
    )
    assert _rules(result.suppressed) == ["K8S-001", "K8S-006"]


def test_path_glob_mismatch_leaves_finding_active(tmp_path: Path) -> None:
    root = _pod(tmp_path)
    result = _scan(root, [{"rule": "K8S-001", "path": "deploy/dev/**", "reason": "dev only"}])
    assert "K8S-001" in _rules(result.findings)
    assert result.suppressed == []


@pytest.mark.parametrize(
    ("resource", "suppressed"),
    [
        ({"kind": "Pod", "name": "debug", "namespace": "dev"}, True),
        ({"kind": "Deployment"}, False),
        ({"namespace": "prod"}, False),
        ({"name": "debug-*"}, False),
        ({"name": "deb*"}, True),
        ({"labels": {"env": "dev"}}, True),
        ({"labels": {"env": "prod"}}, False),
    ],
)
def test_resource_selector(tmp_path: Path, resource: dict, suppressed: bool) -> None:
    root = _pod(tmp_path)
    result = _scan(root, [{"rule": "K8S-001", "resource": resource, "reason": "by design"}])
    assert ("K8S-001" in _rules(result.suppressed)) is suppressed
    assert ("K8S-001" in _rules(result.findings)) is not suppressed


def test_resource_selector_never_matches_a_finding_without_resource_identity(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nRUN pip install flask\n")
    result = _scan(tmp_path, [{"rule": "DOCKER-*", "resource": {"kind": "Pod"}, "reason": "n/a"}])
    assert result.suppressed == []


def test_kubernetes_findings_carry_resource_identity(tmp_path: Path) -> None:
    root = _pod(tmp_path, name="api", namespace="prod", env="prod")
    finding = next(f for f in scan_iac_with_context(root).findings if f.rule_id == "K8S-001")
    assert finding.resource is not None
    assert (finding.resource.kind, finding.resource.name, finding.resource.namespace) == ("Pod", "api", "prod")
    assert finding.resource.labels == {"env": "prod"}


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"rule": "K8S-001"}, "reason"),
        ({"rule": "K8S-001", "reason": "   "}, "reason"),
        ({"rule": "K8S-001", "reason": "x", "expires": "31/12/2026"}, "expires"),
        ({"rule": "K8S-001", "reason": "x", "colour": "red"}, "colour"),
        ({"rule": "K8S-001", "reason": "x", "resource": {"team": "a"}}, "team"),
        ({"rule": "K8S-001", "reason": "x", "resource": {"labels": ["env"]}}, "labels"),
        ({"rule": "*", "reason": "everything"}, "path or resource"),
        ({"type": "iac", "reason": "no rule"}, "rule"),
        ({"rule": "K8S-001", "reason": "x", "owner": 7}, "owner"),
    ],
)
def test_invalid_iac_entries_raise_a_clear_error(entry: dict, message: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        parse_ignore_entries([{"id": "CVE-2024-1"}, entry], origin="ignore.yaml")
    text = str(excinfo.value)
    assert "entry #2" in text
    assert message in text


def test_non_iac_entries_are_left_to_the_vulnerability_ignore_path() -> None:
    assert parse_ignore_entries([{"id": "CVE-2024-1", "reason": "x"}, {"package": "lodash"}], origin="f") == []


def test_yaml_date_objects_are_accepted() -> None:
    [exc] = parse_ignore_entries([{"rule": "K8S-001", "reason": "x", "expires": date(2027, 1, 1)}], origin="f")
    assert exc.expires == date(2027, 1, 1)


# ── expiry ──────────────────────────────────────────────────────────────────


def test_expired_entry_reactivates_and_warns(tmp_path: Path) -> None:
    root = _pod(tmp_path)
    result = _scan(root, [{"rule": "K8S-001", "reason": "temporary", "expires": "2026-10-01", "owner": "sre"}])
    assert "K8S-001" in _rules(result.findings)
    assert result.suppressed == []
    [notice] = [n for n in result.notices if n.kind == "expired"]
    assert notice.rule == "K8S-001"
    assert "2026-10-01" in notice.message and "sre" in notice.message


def test_entry_expiring_today_still_applies(tmp_path: Path) -> None:
    root = _pod(tmp_path)
    result = _scan(root, [{"rule": "K8S-001", "reason": "last day", "expires": TODAY.isoformat()}])
    assert _rules(result.suppressed) == ["K8S-001"]


def test_soon_to_expire_entry_applies_with_a_notice(tmp_path: Path) -> None:
    root = _pod(tmp_path)
    soon = (TODAY + timedelta(days=5)).isoformat()
    result = _scan(root, [{"rule": "K8S-001", "reason": "short window", "expires": soon}])
    assert _rules(result.suppressed) == ["K8S-001"]
    assert result.suppressed[0].suppression["expiring_soon"] is True
    assert [n.kind for n in result.notices] == ["expiring"]


def test_one_notice_per_exception_not_per_finding(tmp_path: Path) -> None:
    root = _pod(tmp_path)
    _pod(root, "k8s/other.yaml", name="other")
    result = _scan(root, [{"rule": "K8S-001", "reason": "temporary", "expires": "2026-01-01"}])
    assert _rules(result.findings).count("K8S-001") == 2
    assert len([n for n in result.notices if n.kind == "expired"]) == 1


# ── inline markers ──────────────────────────────────────────────────────────


def test_inline_marker_with_owner_and_expiry(tmp_path: Path) -> None:
    marker = "        # agent-bom: ignore[K8S-001] expires=2026-12-31 owner=platform-team node debugger needs host access\n"
    root = _pod(tmp_path, marker=marker)
    result = _scan(root)
    assert _rules(result.suppressed) == ["K8S-001"]
    record = result.suppressed[0].suppression
    assert record["source"] == "inline"
    assert record["owner"] == "platform-team"
    assert record["expires"] == "2026-12-31"
    assert record["reason"] == "node debugger needs host access"
    assert record["origin"] == "k8s/pod.yaml:13"


def test_inline_marker_needs_a_reason_after_metadata(tmp_path: Path) -> None:
    root = _pod(tmp_path, marker="        # agent-bom: ignore[K8S-001] expires=2026-12-31 owner=platform-team\n")
    result = _scan(root)
    assert "K8S-001" in _rules(result.findings)
    assert result.suppressed == []


def test_expired_inline_marker_reactivates_and_warns(tmp_path: Path) -> None:
    root = _pod(tmp_path, marker="        # agent-bom: ignore[K8S-001] expires=2026-01-31 debugging window\n")
    result = _scan(root)
    assert "K8S-001" in _rules(result.findings)
    assert [n.kind for n in result.notices] == ["expired"]


def test_inline_marker_with_malformed_expiry_fails_closed(tmp_path: Path) -> None:
    root = _pod(tmp_path, marker="        # agent-bom: ignore[K8S-001] expires=soon debugging window\n")
    result = _scan(root)
    assert "K8S-001" in _rules(result.findings)
    assert [n.kind for n in result.notices] == ["invalid"]


def test_plain_inline_marker_still_works(tmp_path: Path) -> None:
    root = _pod(tmp_path, marker="        # agent-bom: ignore[K8S-001] node debugger\n")
    record = _scan(root).suppressed[0].suppression
    assert record["reason"] == "node debugger"
    assert record["owner"] is None and record["expires"] is None


# ── payload ─────────────────────────────────────────────────────────────────


def test_payload_keeps_suppressed_rows_counts_and_notices(tmp_path: Path) -> None:
    root = _pod(tmp_path)
    result = _scan(
        root,
        [
            {"rule": "K8S-001", "reason": "debug pod", "owner": "platform"},
            {"rule": "K8S-006", "reason": "temporary", "expires": "2026-01-01"},
        ],
    )
    payload = iac_findings_payload(result.findings, result.suppressed, result.notices)
    assert payload["total"] == len(result.findings)
    assert all(row["rule_id"] != "K8S-001" for row in payload["findings"])
    [row] = payload["suppressed"]
    assert row["rule_id"] == "K8S-001"
    assert row["suppressed"] is True
    assert row["suppression"]["reason"] == "debug pod"
    assert row["resource"] == {"kind": "Pod", "name": "debug", "namespace": "dev", "labels": {"env": "dev"}}
    summary = payload["exceptions"]
    assert summary["accepted"] == 1
    assert summary["expired"] == 1
    assert summary["by_source"] == {"ignore_file": 1}
    assert summary["notices"][0]["kind"] == "expired"


def test_exception_ids_are_stable_across_runs() -> None:
    entry = {"rule": "K8S-001", "path": "k8s/*", "reason": "x"}
    first = parse_ignore_entries([entry], origin="f")[0]
    second = parse_ignore_entries([dict(entry)], origin="f")[0]
    assert first.exception_id == second.exception_id
    assert first.exception_id != IaCException(rule="K8S-002", reason="x", source="ignore_file", origin="f#1").exception_id


def test_untrusted_inline_text_is_bounded(tmp_path: Path) -> None:
    root = _pod(tmp_path, marker="        # agent-bom: ignore[K8S-001] owner=" + "o" * 900 + " " + "r" * 5000 + "\n")
    record = _scan(root).suppressed[0].suppression
    assert len(record["reason"]) == 500
    assert len(record["owner"]) == 500


def test_resource_selector_label_count_is_bounded() -> None:
    labels = {f"k{i}": "v" for i in range(33)}
    with pytest.raises(ValueError, match="more than 32 labels"):
        parse_ignore_entries([{"rule": "K8S-001", "reason": "x", "resource": {"labels": labels}}], origin="f")


def test_resource_selector_matches_labels_as_a_subset() -> None:
    from agent_bom.iac.models import IaCResourceRef

    selector = ResourceSelector(labels=(("env", "dev"),))
    assert selector.matches(IaCResourceRef(kind="Pod", name="a", namespace="", labels={"env": "dev", "team": "x"}))
    assert not selector.matches(IaCResourceRef(kind="Pod", name="a", namespace="", labels={"team": "x"}))
