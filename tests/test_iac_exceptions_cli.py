"""End to end: `agent-bom iac` and `agent-bom scan --iac` honour IaC exceptions and policy, and keep the evidence."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

POD = """apiVersion: v1
kind: Pod
metadata:
  name: debug
  namespace: {namespace}
  labels:
    env: {env}
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: nginx:1.25@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      resources:
        limits: {{cpu: "1", memory: 1Gi}}
      securityContext:
        privileged: true
        readOnlyRootFilesystem: true
"""

POLICY = {
    "name": "iac-guardrails",
    "environments": {"prod": ["deploy/prod/**"], "dev": ["deploy/dev/**"]},
    "rules": [
        {
            "id": "no-privileged-prod",
            "description": "Privileged pods are blocked in prod",
            "iac_rule": "K8S-001",
            "iac_environment": "prod",
            "action": "block",
        },
        {
            "id": "privileged-dev-warn",
            "description": "Privileged pods in dev are reviewed",
            "iac_rule": "K8S-001",
            "iac_environment": "dev",
            "action": "warn",
        },
    ],
}


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    for env in ("prod", "dev"):
        path = tmp_path / "deploy" / env / "pod.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(POD.format(namespace=env, env=env))
    return tmp_path


def _ignore(root: Path, entries: list[dict]) -> Path:
    import yaml

    path = root / ".agent-bom-ignore.yaml"
    path.write_text(yaml.safe_dump({"ignores": entries}))
    return path


def _run(*args: str):
    return CliRunner().invoke(main, list(args), catch_exceptions=False)


def _json(output: str) -> dict:
    return json.loads(output[output.index("{") :])


def _critical_rules(payload: dict) -> list[tuple[str, str]]:
    return sorted((row["rule_id"], row["file_path"]) for row in payload["findings"] if row["severity"] in {"critical", "high"})


def test_without_exceptions_privileged_pods_fail_the_gate(repo: Path) -> None:
    result = _run("iac", "deploy", "-f", "json", "--fail-on-severity", "high")
    assert result.exit_code == 1
    assert ("K8S-001", "dev/pod.yaml") in _critical_rules(_json(result.output))


def test_default_ignore_file_accepts_dev_and_keeps_prod_blocking(repo: Path) -> None:
    _ignore(repo, [{"rule": "K8S-001", "path": "deploy/dev/*", "reason": "debug pods in dev", "owner": "platform"}])
    result = _run("iac", "deploy", "-f", "json", "--fail-on-severity", "high")
    assert result.exit_code == 1  # prod is still privileged
    payload = _json(result.output)
    assert _critical_rules(payload) == [("K8S-001", "prod/pod.yaml")]
    [row] = payload["suppressed"]
    assert (row["rule_id"], row["file_path"]) == ("K8S-001", "dev/pod.yaml")
    assert row["suppression"]["reason"] == "debug pods in dev"
    assert row["suppression"]["source"] == "ignore_file"
    assert payload["exceptions"]["accepted"] == 1


def test_all_privileged_pods_accepted_passes_the_gate(repo: Path) -> None:
    ignore = _ignore(
        repo, [{"rule": "K8S-001", "resource": {"kind": "Pod", "name": "debug"}, "reason": "node debugger", "expires": "2099-01-01"}]
    )
    result = _run("iac", "deploy", "-f", "json", "--fail-on-severity", "high", "--ignore-file", str(ignore))
    assert result.exit_code == 0, result.output
    assert len(_json(result.output)["suppressed"]) == 2


def test_expired_exception_reactivates_and_warns(repo: Path) -> None:
    expired = (date.today() - timedelta(days=1)).isoformat()
    _ignore(repo, [{"rule": "K8S-001", "path": "deploy/*", "reason": "temporary", "owner": "sre", "expires": expired}])
    result = _run("iac", "deploy", "--fail-on-severity", "high")
    assert result.exit_code == 1
    text = " ".join(result.output.split())
    assert "expired" in text and expired in text and "sre" in text


def test_soon_to_expire_exception_prints_a_notice(repo: Path) -> None:
    soon = (date.today() + timedelta(days=3)).isoformat()
    _ignore(repo, [{"rule": "K8S-001", "path": "deploy/*", "reason": "temporary", "expires": soon}])
    result = _run("iac", "deploy", "--fail-on-severity", "high")
    assert result.exit_code == 0, result.output
    text = " ".join(result.output.split())
    assert "2 accepted exception(s)" in text
    assert f"expires on {soon}" in text


def test_invalid_ignore_entry_stops_the_scan_with_a_clear_error(repo: Path) -> None:
    _ignore(repo, [{"rule": "K8S-001", "path": "deploy/*"}])
    result = _run("iac", "deploy")
    assert result.exit_code == 1
    text = " ".join(result.output.split())
    assert "Error:" in text and "entry #1" in text and "reason" in text
    assert "K8S-001" in text and "Privileged container" not in text


def test_policy_blocks_prod_and_warns_dev(repo: Path) -> None:
    policy = repo / "policy.json"
    policy.write_text(json.dumps(POLICY))
    result = _run("iac", "deploy", "-f", "json", "--fail-on-severity", "critical", "--policy", str(policy))
    payload = _json(result.output)
    assert [(v["rule_id"], v["environment"]) for v in payload["policy"]["failures"]] == [("no-privileged-prod", "prod")]
    assert [(v["rule_id"], v["environment"]) for v in payload["policy"]["warnings"]] == [("privileged-dev-warn", "dev")]
    assert result.exit_code == 1


def test_policy_block_fails_even_without_a_severity_gate(repo: Path) -> None:
    policy = repo / "policy.json"
    policy.write_text(json.dumps(POLICY))
    _ignore(repo, [{"rule": "K8S-006", "path": "deploy/*", "reason": "n/a"}])
    result = _run("iac", "deploy", "-f", "sarif", "-o", str(repo / "out.sarif"), "--policy", str(policy))
    assert result.exit_code == 1


def test_sarif_keeps_accepted_exceptions_as_suppressed_results(repo: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    _ignore(repo, [{"rule": "K8S-001", "path": "deploy/dev/*", "reason": "debug pods in dev", "owner": "platform"}])
    out = repo / "out.sarif"
    _run("iac", "deploy", "-f", "sarif", "-o", str(out))
    sarif = json.loads(out.read_text())
    schema = json.loads((Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json").read_text())
    jsonschema.Draft7Validator(schema).validate(sarif)
    results = sarif["runs"][0]["results"]
    suppressed = [r for r in results if r.get("suppressions")]
    assert len(suppressed) == 1
    [entry] = suppressed[0]["suppressions"]
    assert entry["kind"] == "external"
    assert entry["status"] == "accepted"
    assert entry["justification"] == "debug pods in dev"
    assert entry["properties"]["owner"] == "platform"
    active_privileged = [r for r in results if r["ruleId"] == "iac/K8S-001" and not r.get("suppressions")]
    assert len(active_privileged) == 1


def test_inline_marker_shows_as_in_source_suppression(repo: Path) -> None:
    path = repo / "deploy" / "dev" / "pod.yaml"
    path.write_text(
        path.read_text().replace(
            "        privileged: true", "        # agent-bom: ignore[K8S-001] owner=platform debugger\n        privileged: true"
        )
    )
    out = repo / "out.sarif"
    _run("iac", "deploy", "-f", "sarif", "-o", str(out))
    results = json.loads(out.read_text())["runs"][0]["results"]
    [entry] = next(r for r in results if r.get("suppressions"))["suppressions"]
    assert entry["kind"] == "inSource"


def test_html_report_lists_accepted_exceptions(repo: Path) -> None:
    _ignore(repo, [{"rule": "K8S-001", "path": "deploy/dev/*", "reason": "debug <pods> in dev", "owner": "platform"}])
    out = repo / "report.html"
    _run("iac", "deploy", "-f", "html", "-o", str(out))
    html = out.read_text()
    assert "1 accepted IaC exception(s)" in html
    assert "debug &lt;pods&gt; in dev" in html
    assert "<pods>" not in html


def test_scan_iac_uses_the_same_exceptions(repo: Path) -> None:
    _ignore(repo, [{"rule": "K8S-001", "path": "deploy/dev/*", "reason": "debug pods in dev"}])
    out = repo / "scan.json"
    result = _run("scan", "--iac", "deploy", "--no-scan", "-f", "json", "-o", str(out), "--fail-on-severity", "critical")
    payload = json.loads(out.read_text())
    iac = payload["iac_findings"]
    assert [row["file_path"] for row in iac["suppressed"]] == ["dev/pod.yaml"]
    assert iac["exceptions"]["by_source"] == {"ignore_file": 1}
    unified = [f for f in payload["findings"] if f.get("evidence", {}).get("iac") and f.get("evidence", {}).get("rule_id") == "K8S-001"]
    assert len(unified) == 1  # the accepted one does not reach the unified gate stream
    assert result.exit_code == 1  # prod is still critical


def _sbom(root: Path) -> Path:
    path = root / "bom.cdx.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "requests", "version": "2.32.3", "purl": "pkg:pypi/requests@2.32.3"}],
            }
        )
    )
    return path


@pytest.mark.parametrize("explicit", [False, True])
def test_malformed_iac_entry_fails_a_run_without_iac_paths(tmp_path: Path, monkeypatch, explicit: bool) -> None:
    monkeypatch.chdir(tmp_path)
    ignore = _ignore(tmp_path, [{"rule": "K8S-001", "path": "deploy/*"}])
    args = ["scan", "--sbom", str(_sbom(tmp_path)), "--no-scan", "-f", "json", "-o", str(tmp_path / "out.json")]
    result = _run(*args, *(["--ignore-file", str(ignore)] if explicit else []))
    assert result.exit_code == 1
    text = " ".join(result.output.split())
    assert "Error:" in text and "entry #1" in text and "reason" in text
    assert not (tmp_path / "out.json").exists()


def test_valid_iac_entries_do_not_disturb_a_run_without_iac_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _ignore(tmp_path, [{"rule": "K8S-001", "path": "deploy/*", "reason": "debug pods"}])
    result = _run("scan", "--sbom", str(_sbom(tmp_path)), "--no-scan", "-f", "json", "-o", str(tmp_path / "out.json"))
    assert "Error:" not in result.output  # --no-scan exits 1 as a partial-scan verdict; validation passed
    assert (tmp_path / "out.json").exists()
