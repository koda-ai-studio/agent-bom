from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "gitleaks.yml"


def test_gitleaks_scans_event_git_ranges_without_github_api_dependency() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "gitleaks/gitleaks-action@" not in workflow
    assert "GITHUB_TOKEN" not in workflow
    assert "GITLEAKS_LICENSE" not in workflow
    assert "GITLEAKS_ENABLE_COMMENTS" not in workflow
    assert "GITLEAKS_ENABLE_UPLOAD_ARTIFACT" not in workflow
    assert "github.event.pull_request.base.sha" in workflow
    assert "github.event.pull_request.head.sha" in workflow
    assert "github.event.before" in workflow
    assert "git cat-file -e" in workflow
    assert "--log-opts" in workflow


def test_gitleaks_binary_and_scan_contract_are_fail_closed() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "timeout-minutes: 15" in workflow
    assert "fetch-depth: 0" in workflow
    assert "persist-credentials: false" in workflow
    assert 'GITLEAKS_VERSION: "8.24.3"' in workflow
    assert 'GITLEAKS_ARCHIVE_SHA256: "9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c"' in workflow
    assert "https://github.com/gitleaks/gitleaks/releases/download/" in workflow
    assert "sha256sum --check --strict" in workflow
    assert "set -euo pipefail" in workflow
    assert "--config .gitleaks.toml" in workflow
    assert "--gitleaks-ignore-path .gitleaksignore" in workflow
    assert "--redact=100" in workflow


def test_characterization_hostname_exception_does_not_hide_other_values() -> None:
    import json
    import re
    import tomllib

    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    patterns = [re.compile(value) for value in config["allowlist"]["regexes"] if "api_server_fqdn" in value]
    assert len(patterns) == 1
    pattern = patterns[0]
    hostname = "private.azmk8s.io"
    field = "api_server_fqdn"

    def line(values: dict[str, str]) -> str:
        return "  " + json.dumps(values)[1:-1] + ","

    assert pattern.fullmatch(line({field: hostname}))
    assert not pattern.fullmatch(line({field: hostname + ".attacker.example"}))
    assert not pattern.fullmatch(line({field: "another-value"}))
    assert not pattern.fullmatch(line({"api_key": hostname}))
    assert not pattern.fullmatch(line({field: hostname, "api_key": "another-value"}))


def test_graph_fixture_exception_only_accepts_scoped_server_uuid_labels() -> None:
    import re
    import tomllib

    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    patterns = [re.compile(value) for value in config["allowlist"]["regexes"] if "server:cfg-" in value]
    assert len(patterns) == 1
    node_id = "-".join(("575e032b", "5e58", "539e", "85c6", "cd9eba4abff2"))
    line = f'  "server:cfg-e12ed29252b1:api-agent:{node_id}": "api-agent-server",'
    assert patterns[0].fullmatch(line)
    for changed in (
        line.replace("api-agent-server", "secret-value"),
        line.replace(node_id, "secret-value"),
        line.replace("server:cfg-", "api-key:cfg-"),
        line + ' "api_key": "secret-value"',
    ):
        assert not patterns[0].fullmatch(changed)
