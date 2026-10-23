"""agent-bom-guard: command parsing, verdicts, data parity and the hook contract."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from agent_bom import malicious

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "integrations" / "agent-bom-guard"
SCRIPT = GUARD / "hooks" / "install_guard.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


guard = _load_module("install_guard", SCRIPT)


def _pkgs(command):
    return [(p.ecosystem, p.name, p.version) for p in guard.parse_command(command).packages]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("npm install express", [("npm", "express", None)]),
        ("npm i -D left-pad@1.3.0", [("npm", "left-pad", "1.3.0")]),
        ("npm add @scope/pkg@2.0.1 lodash@^4.17.0", [("npm", "@scope/pkg", "2.0.1"), ("npm", "lodash", None)]),
        ("npm install --save-dev --registry https://r.example.invalid typescript", [("npm", "typescript", None)]),
        ("pnpm add zod@3.23.8", [("npm", "zod", "3.23.8")]),
        ("yarn add react react-dom@18.3.1", [("npm", "react", None), ("npm", "react-dom", "18.3.1")]),
        ("bun add hono", [("npm", "hono", None)]),
        (
            "npx -y @modelcontextprotocol/server-filesystem@2025.1.14 /tmp",
            [("npm", "@modelcontextprotocol/server-filesystem", "2025.1.14")],
        ),
        (
            "pip install requests==2.19.0 'flask>=2' \"django[argon2]==4.2.1\"",
            [("pypi", "requests", "2.19.0"), ("pypi", "flask", None), ("pypi", "django", "4.2.1")],
        ),
        ("pip3 install -U --index-url https://pypi.example.invalid/simple numpy", [("pypi", "numpy", None)]),
        ("python3 -m pip install --user httpx==0.27.0", [("pypi", "httpx", "0.27.0")]),
        ("uv pip install --system pydantic==2.8.2", [("pypi", "pydantic", "2.8.2")]),
        ("uv add 'fastapi==0.115.0' --dev ruff", [("pypi", "fastapi", "0.115.0"), ("pypi", "ruff", None)]),
        ("poetry add --group dev pytest@8.3.2", [("pypi", "pytest", "8.3.2")]),
        ("pipx install black", [("pypi", "black", None)]),
        ("uvx ruff@0.6.9 check .", [("pypi", "ruff", "0.6.9")]),
        ("uvx --from 'mcp-server-git==0.6.2' mcp-server-git", [("pypi", "mcp-server-git", "0.6.2")]),
        ("cargo add serde@1.0.200 tokio --features full", [("cargo", "serde", "1.0.200"), ("cargo", "tokio", None)]),
        ("cargo install ripgrep --version 14.1.0", [("cargo", "ripgrep", "14.1.0")]),
        ("go get github.com/gin-gonic/gin@v1.9.1", [("go", "github.com/gin-gonic/gin", "1.9.1")]),
        ("go install golang.org/x/tools/gopls@latest", [("go", "golang.org/x/tools/gopls", None)]),
        ("cd web && npm install axios && npm test", [("npm", "axios", None)]),
        ("make build; pip install rich || echo failed", [("pypi", "rich", None)]),
        ("sudo -E PIP_NO_CACHE=1 pip install six", [("pypi", "six", None)]),
        ("bash -c 'npm install chalk@5.3.0'", [("npm", "chalk", "5.3.0")]),
        ("pip install \\\n  requests \\\n  urllib3==2.2.2", [("pypi", "requests", None), ("pypi", "urllib3", "2.2.2")]),
        ("npm install\npip install tqdm", [("pypi", "tqdm", None)]),
        ("sudo -H -u builder pip install six==1.16.0", [("pypi", "six", "1.16.0")]),
        ("env -u HOME FOO=1 npm i chalk", [("npm", "chalk", None)]),
        ("nohup npm install chalk; time pip install rich", [("npm", "chalk", None), ("pypi", "rich", None)]),
        ("pip install \"rich==13.7.1\" 'six'", [("pypi", "rich", "13.7.1"), ("pypi", "six", None)]),
        ("npm test && npm install left-pad || true", [("npm", "left-pad", None)]),
    ],
)
def test_parses_package_installs(command, expected):
    assert _pkgs(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        "npm install",
        "npm ci",
        "yarn",
        "pip install -e .",
        "pip install ./dist/pkg-1.0-py3-none-any.whl",
        "pip install git+https://github.com/org/repo.git",
        "npm install github:user/repo file:../local https://example.invalid/pkg.tgz",
        "uv sync --frozen",
        "cargo add --path ../local-crate",
        "echo 'npm install evil-pkg'",
        "grep -r 'pip install' docs/",
        "git commit -m 'pip install fix'",
        "ls -la",
        "npm run install-deps",
        "pip install $(cat pkgs.txt)",
        "npm install `cat pkgs`",
        "pip download requests",
        "",
    ],
)
def test_commands_that_install_no_named_registry_package(command):
    assert _pkgs(command) == []


@pytest.mark.parametrize(
    ("command", "files"),
    [
        ("pip install -r requirements.txt", ["requirements.txt"]),
        ("pip install -r requirements-dev.txt -c constraints.txt", ["requirements-dev.txt", "constraints.txt"]),
        ("uv pip install --requirement=reqs/base.txt", ["reqs/base.txt"]),
    ],
)
def test_requirement_files_are_reported(command, files):
    plan = guard.parse_command(command)
    assert plan.packages == []
    assert plan.requirement_files == files


def test_unbalanced_quotes_do_not_crash():
    assert guard.parse_command("npm install 'left-pad").packages == []


def test_shell_text_is_never_executed(tmp_path):
    marker = tmp_path / "ran"
    plan = guard.parse_command(f"pip install $(touch {marker}) && npm install `touch {marker}`")
    assert plan.packages == [] and not marker.exists()
    assert guard.decide(_event(f"bash -c 'touch {marker}; pip install rich'"), {}, FakeOSV()) is None
    assert not marker.exists()


class FakeOSV:
    def __init__(self, vulns=None, details=None, fail=False):
        self.vulns = vulns or {}
        self.details = details or {}
        self.fail = fail
        self.queries = []

    def query(self, packages, timeout):
        self.queries.append(list(packages))
        if self.fail:
            raise TimeoutError("timed out")
        return [self.vulns.get(p.name, []) for p in packages]

    def detail(self, vuln_id, timeout):
        return self.details.get(vuln_id, {})


def _event(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}


def _decide(command, osv=None, **options):
    env = {f"CLAUDE_PLUGIN_OPTION_{k.upper()}": v for k, v in options.items()}
    return guard.decide(_event(command), env, osv or FakeOSV())


def _decision(out):
    return (out or {}).get("hookSpecificOutput", {}).get("permissionDecision")


def _reason(out):
    return out["hookSpecificOutput"]["permissionDecisionReason"]


def test_non_install_commands_produce_no_output_and_no_lookup():
    osv = FakeOSV()
    for command in ("pytest -q", "echo 'pip install reqeusts'", "git commit -m 'npm install expres'", "pip install -e ."):
        assert _decide(command, osv) is None
    assert osv.queries == []


def test_other_tools_and_events_are_ignored():
    osv = FakeOSV()
    event = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"command": "pip install reqeusts"}}
    assert guard.decide(event, {}, osv) is None
    assert guard.decide({"tool_name": "Bash", "tool_input": {"command": 7}}, {}, osv) is None
    assert osv.queries == []


def test_clean_install_passes_silently():
    assert _decide("npm install express@4.21.0") is None


def test_clean_install_never_emits_allow():
    # "allow" would skip the user's own permission prompt; the guard only ever denies or stays out of the way.
    for command in ("npm install express@4.21.0", "pip install rich==13.7.1", "pip install -r requirements.txt"):
        assert _decision(_decide(command)) is None


def test_typosquat_is_blocked_with_the_imitated_name():
    out = _decide("pip install reqeusts")
    assert _decision(out) == "deny"
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    reason = _reason(out)
    assert "reqeusts" in reason and "requests" in reason
    assert "reqeusts" in out["systemMessage"]


@pytest.mark.parametrize(
    "command",
    [
        "cd api && pip install reqeusts",
        "make; pip install reqeusts",
        "sudo pip install reqeusts",
        "sudo -H pip install reqeusts",
        "PIP_NO_CACHE_DIR=1 pip install reqeusts",
        "pip install 'reqeusts==2.31.0'",
        'pip install "reqeusts"',
        "npm test && FOO=1 npm install expres",
        "bash -lc 'pip install reqeusts'",
    ],
)
def test_typosquat_blocked_through_chains_prefixes_and_quotes(command):
    out = _decide(command)
    assert _decision(out) == "deny", command


def test_osv_malicious_report_is_blocked():
    out = _decide("npm install totally-new-pkg", FakeOSV(vulns={"totally-new-pkg": ["MAL-2025-1"]}))
    assert _decision(out) == "deny"
    assert "MAL-2025-1" in _reason(out)


def test_osv_malicious_report_on_unversioned_install_is_still_blocked():
    out = _decide("npm install totally-new-pkg", FakeOSV(vulns={"totally-new-pkg": ["MAL-2025-1", "GHSA-old"]}))
    assert _decision(out) == "deny"
    assert "GHSA-old" not in json.dumps(out)


def test_bundled_malicious_name_is_blocked_even_when_osv_is_unreachable():
    out = _decide("npx -y postmark-mcp", FakeOSV(fail=True))
    assert _decision(out) == "deny"
    assert "postmark-mcp" in _reason(out)


def test_bundled_malicious_version_range_is_respected():
    assert _decision(_decide("npm install postmark-mcp@1.0.16", osv_lookup="false")) == "deny"
    out = _decide("npm install postmark-mcp@1.0.15", osv_lookup="false")
    assert _decision(out) is None
    assert "postmark-mcp" in out["systemMessage"]


def test_cves_warn_without_blocking_and_name_severity():
    osv = FakeOSV(
        vulns={"lodash": ["GHSA-35jh-r3h4-6jhm", "GHSA-xxxx"]},
        details={"GHSA-35jh-r3h4-6jhm": {"database_specific": {"severity": "CRITICAL"}, "summary": "Command Injection in lodash"}},
    )
    out = _decide("npm install lodash@4.17.20", osv)
    assert _decision(out) is None
    assert "GHSA-35jh-r3h4-6jhm" in out["systemMessage"] and "critical" in out["systemMessage"].lower()
    assert "lodash@4.17.20" in out["hookSpecificOutput"]["additionalContext"]


def test_aliased_advisories_are_counted_once():
    osv = FakeOSV(
        vulns={"github.com/gin-gonic/gin": ["GHSA-2c4m-59x9-fr2g", "GO-2023-1737"]},
        details={
            "GHSA-2c4m-59x9-fr2g": {"aliases": ["CVE-2023-29401"], "database_specific": {"severity": "MODERATE"}},
            "GO-2023-1737": {"aliases": ["CVE-2023-29401", "GHSA-2c4m-59x9-fr2g"]},
        },
    )
    message = _decide("go get github.com/gin-gonic/gin@v1.9.0", osv)["systemMessage"]
    assert "1 known advisory:" in message and "GHSA-2c4m-59x9-fr2g (moderate)" in message
    assert "GO-2023-1737" not in message


def test_withdrawn_advisories_are_dropped():
    osv = FakeOSV(vulns={"lodash": ["GHSA-gone"]}, details={"GHSA-gone": {"withdrawn": "2024-01-01T00:00:00Z"}})
    assert _decide("npm install lodash@4.17.20", osv) is None


def test_cve_on_one_package_does_not_hide_a_typosquat_block():
    osv = FakeOSV(vulns={"lodash": ["GHSA-35jh-r3h4-6jhm"]})
    out = _decide("npm install lodash@4.17.20 && pip install reqeusts", osv)
    assert _decision(out) == "deny"
    assert "GHSA-35jh-r3h4-6jhm" in out["hookSpecificOutput"]["additionalContext"]


def test_unversioned_install_ignores_historical_cves():
    out = _decide("npm install lodash", FakeOSV(vulns={"lodash": ["GHSA-35jh-r3h4-6jhm"]}))
    assert out is None


def test_unreachable_osv_warns_instead_of_silently_passing():
    out = _decide("pip install rich", FakeOSV(fail=True))
    assert _decision(out) is None
    assert "api.osv.dev" in out["systemMessage"]


def test_osv_lookup_can_be_turned_off_and_stays_silent_on_clean_installs():
    osv = FakeOSV()
    assert _decide("pip install rich==13.7.1", osv, osv_lookup="false") is None
    assert _decision(_decide("pip install reqeusts", osv, osv_lookup="false")) == "deny"
    assert osv.queries == []


@pytest.mark.parametrize(("mode", "decision"), [("block", "deny"), ("warn", None), ("BLOCK", "deny"), ("bogus", "deny"), ("", "deny")])
def test_on_match_mode(mode, decision):
    out = _decide("pip install reqeusts", on_match=mode)
    assert _decision(out) == decision
    assert "reqeusts" in out["systemMessage"]


def test_warn_mode_still_tells_the_agent():
    out = _decide("pip install reqeusts", on_match="warn")
    assert "requests" in out["hookSpecificOutput"]["additionalContext"]


def test_requirement_files_are_reported_not_blocked():
    out = _decide("pip install -r requirements.txt")
    assert _decision(out) is None
    assert "requirements.txt" in out["systemMessage"]


def test_osv_client_sends_only_name_ecosystem_and_version(monkeypatch):
    sent = []

    class Response:
        def __init__(self, body):
            self.body = body

        def read(self, limit=-1):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout):
        sent.append((request.full_url, request.data, timeout))
        return Response(b'{"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    packages = [guard.Package("pypi", "requests", "2.19.0"), guard.Package("go", "github.com/gin-gonic/gin", None)]
    assert guard.OSVClient().query(packages, timeout=2.5) == [["GHSA-1"], []]
    url, body, timeout = sent[0]
    assert url == "https://api.osv.dev/v1/querybatch" and timeout == 2.5
    assert json.loads(body) == {
        "queries": [
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"},
            {"package": {"name": "github.com/gin-gonic/gin", "ecosystem": "Go"}},
        ]
    }


def test_internal_errors_fail_open_with_a_note(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(guard, "decide", boom)
    out = json.loads(guard.run(json.dumps(_event("pip install rich")), {}, FakeOSV()))
    assert "permissionDecision" not in json.dumps(out)
    assert "agent-bom-guard" in out["systemMessage"] and "not checked" in out["systemMessage"]


def test_bundled_data_matches_the_generator():
    generator = _load_module("generate_guard_data", ROOT / "scripts" / "generate_guard_data.py")
    assert (GUARD / "hooks" / "guard_data.json").read_text() == generator.render()


def test_bundled_data_is_derived_from_agent_bom_sources():
    data = json.loads((GUARD / "hooks" / "guard_data.json").read_text())
    assert data["popular"] == {k: sorted(v) for k, v in malicious._POPULAR_PACKAGES.items()}
    assert data["known_legitimate"] == {k: sorted(v) for k, v in malicious._KNOWN_LEGITIMATE.items()}
    assert data["safe_npm_scopes"] == sorted(malicious._SAFE_NPM_SCOPES)
    blocklist = json.loads((Path(malicious.__file__).parent / "data" / "mcp-blocklist.json").read_text())
    confirmed = sorted(
        [e["ecosystem"], e["package"], e.get("affected_versions") or "*", e["id"]]
        for e in blocklist["entries"]
        if e.get("package") and e.get("confidence") == "confirmed_malicious"
    )
    assert data["known_malicious"] == confirmed
    assert confirmed


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [
        ("reqeusts", "pypi"),
        ("requests", "pypi"),
        ("djanga", "pypi"),
        ("panda", "pypi"),
        ("httpx2", "pypi"),
        ("boto", "pypi"),
        ("pydantic2", "pypi"),
        ("expres", "npm"),
        ("express", "npm"),
        ("bcryptjs", "npm"),
        ("@babel/core", "npm"),
        ("lodahs", "npm"),
        ("left-pad", "npm"),
        ("serde", "cargo"),
    ],
)
def test_typosquat_matches_agent_bom(name, ecosystem):
    assert guard.check_typosquat(name, ecosystem) == malicious.check_typosquat(name, ecosystem)


def test_hook_manifest_runs_the_script_on_bash_in_exec_form():
    hooks = json.loads((GUARD / "hooks" / "hooks.json").read_text())["hooks"]
    assert list(hooks) == ["PreToolUse"]
    entries = hooks["PreToolUse"]
    assert len(entries) == 1 and entries[0]["matcher"] == "Bash"
    handler = entries[0]["hooks"][0]
    assert handler["type"] == "command" and handler["command"] == "python3"
    assert handler["args"] == ["-I", "${CLAUDE_PLUGIN_ROOT}/hooks/install_guard.py"]
    assert 0 < handler["timeout"] <= 10


def test_manifest_declares_the_options_the_script_reads():
    manifest = json.loads((GUARD / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] == "agent-bom-guard" and manifest["license"] == "Apache-2.0"
    options = manifest["userConfig"]
    assert set(options) == {"on_match", "osv_lookup"}
    assert options["on_match"]["options"] == ["block", "warn"] and options["on_match"]["default"] == "block"
    assert options["osv_lookup"]["type"] == "boolean" and options["osv_lookup"]["default"] is True
    assert guard.DEFAULTS == {"on_match": "block", "osv_lookup": True}


def test_manifest_version_tracks_the_published_release():
    manifest = json.loads((GUARD / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["version"] == (ROOT / "PUBLISHED_VERSION").read_text().strip()


def test_marketplace_lists_the_guard_beside_agent_bom():
    marketplace = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    entries = {p["name"]: p for p in marketplace["plugins"]}
    assert entries["agent-bom-guard"]["source"] == "./integrations/agent-bom-guard"
    assert "agent-bom" in entries


def test_plugin_folder_has_no_launchers_or_installs_in_the_hook_scripts():
    for path in (GUARD / "hooks").glob("*.py"):
        text = path.read_text()
        for forbidden in ("subprocess", "os.system", "os.exec", "os.popen", "pty", "eval(", "exec("):
            assert forbidden not in text, (path.name, forbidden)


def test_decide_offline_is_fast():
    commands = ["pip install reqeusts", "cd web && npm install axios@1.7.2 lodash", "ls -la"]
    for command in commands:
        _decide(command, osv_lookup="false")
    started = time.perf_counter()
    for _ in range(20):
        for command in commands:
            _decide(command, osv_lookup="false")
    assert (time.perf_counter() - started) / (20 * len(commands)) < 0.15


def _run(command, **env):
    event = json.dumps(_event(command))
    started = time.monotonic()
    proc = subprocess.run(
        ["python3", "-I", str(SCRIPT)],
        input=event,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", **env},
        timeout=20,
    )
    return proc, time.monotonic() - started


def test_script_end_to_end_is_fast_offline():
    proc, elapsed = _run("ls -la")
    assert proc.returncode == 0 and proc.stdout == ""
    assert elapsed < 1.5
    proc, elapsed = _run("pip install reqeusts", CLAUDE_PLUGIN_OPTION_OSV_LOOKUP="false")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert elapsed < 1.5


def test_script_runs_on_the_system_python3():
    # /usr/bin/python3 is what the hook's bare `python3` resolves to on a stock Mac (3.9).
    proc, _ = _run("npm install expres", CLAUDE_PLUGIN_OPTION_OSV_LOOKUP="false")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("stdin", ["not json", "", "[]", '{"tool_name": "Bash"}', '{"tool_name": "Bash", "tool_input": "x"}'])
def test_malformed_input_never_blocks(stdin):
    proc = subprocess.run(["python3", "-I", str(SCRIPT)], input=stdin, capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0 and proc.stdout == ""


@pytest.mark.parametrize("python", ["python3", sys.executable])
def test_script_writes_nothing_into_the_plugin_folder(tmp_path, python):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for name in ("install_guard.py", "command_parser.py", "guard_data.json"):
        (hooks / name).write_bytes((GUARD / "hooks" / name).read_bytes())
    event = json.dumps(_event("pip install reqeusts"))
    env = {"PATH": "/usr/bin:/bin", "CLAUDE_PLUGIN_OPTION_OSV_LOOKUP": "false"}
    proc = subprocess.run([python, "-I", str(hooks / "install_guard.py")], input=event, capture_output=True, text=True, env=env, timeout=20)
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert sorted(p.name for p in hooks.iterdir()) == ["command_parser.py", "guard_data.json", "install_guard.py"]
