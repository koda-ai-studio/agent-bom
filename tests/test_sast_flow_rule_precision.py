"""Precision of the outbound-URL, deserialization and helper-chain flow rules.

False-positive shapes are lifted from agent-bom's own dogfood alerts; each is
paired with a true-positive shape that differs only where input gets in.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agent_bom.ast_analyzer import analyze_project


def _findings(tmp_path: Path, source: str, category: str, *, name: str = "mod.py") -> list:
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")
    result = analyze_project(tmp_path)
    return [finding for finding in result.flow_findings if finding.category == category]


# ─── Outbound URL construction ───────────────────────────────────────────────

SAFE_URLS = {
    # model_hash.py: the scheme and host are fixed by a literal.
    "literal-host": """
        import httpx

        def fetch(repo_id):
            return httpx.get(f"https://huggingface.co/api/models/{repo_id}")
    """,
    # model_hash.py: a module constant base followed by a path.
    "constant-base-then-path": """
        import httpx

        _HF_API = "https://huggingface.co/api"

        def fetch(repo_id):
            url = f"{_HF_API}/models/{repo_id}"
            return httpx.get(url, timeout=15.0)
    """,
    # ai_components/provider_discovery.py: an imported operator-configuration constant.
    "imported-config-constant-base": """
        import httpx
        from agent_bom.config import OLLAMA_BASE_URL

        def detect():
            return httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2.0)
    """,
    # agent_identity.py: the URL passes the outbound URL guard first.
    "validated-before-request": """
        import httpx
        from agent_bom.security import validate_url

        def discover(issuer):
            discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
            validate_url(discovery_url)
            return httpx.get(discovery_url, timeout=10.0)
    """,
}

UNSAFE_URLS = {
    "parameter-host": """
        import httpx

        def probe(host):
            return httpx.get(f"{host}/api/tags", timeout=5.0)
    """,
    "host-inside-authority": """
        import httpx

        def probe(host):
            return httpx.get(f"https://{host}/api/tags")
    """,
    "literal-scheme-concatenated-host": """
        import httpx

        def probe(host):
            return httpx.get("https://" + host + "/x")
    """,
    "authority-left-open": """
        import httpx

        def probe(path):
            return httpx.get(f"https://api.example.com{path}")
    """,
    "constant-base-without-separator": """
        import httpx

        BASE = "https://api.example.com"

        def probe(suffix):
            return httpx.get(f"{BASE}{suffix}")
    """,
    "a-different-name-validated": """
        import httpx
        from agent_bom.security import validate_url

        def probe(other, host):
            validate_url(other)
            url = f"{host}/x"
            return httpx.get(url)
    """,
    "validated-after-request": """
        import httpx
        from agent_bom.security import validate_url

        def probe(host):
            url = f"{host}/x"
            response = httpx.get(url)
            validate_url(url)
            return response
    """,
}


@pytest.mark.parametrize("shape", sorted(SAFE_URLS))
def test_pinned_or_validated_url_is_not_reported(tmp_path: Path, shape: str) -> None:
    assert _findings(tmp_path, SAFE_URLS[shape], "ssrf_url_construction") == []


@pytest.mark.parametrize("shape", sorted(UNSAFE_URLS))
def test_url_whose_host_can_vary_is_reported(tmp_path: Path, shape: str) -> None:
    assert len(_findings(tmp_path, UNSAFE_URLS[shape], "ssrf_url_construction")) == 1, shape


# ─── YAML loaders ────────────────────────────────────────────────────────────

_SAFE_SUBCLASS = """
    import yaml

    class _LineLoader(yaml.SafeLoader):
        pass

    class _Nested(_LineLoader):
        pass

    _LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, lambda loader, node: {})

    def one(content):
        return yaml.load(content, Loader=_LineLoader)

    def many(content):
        return list(yaml.load_all(content, Loader=_Nested))
"""


def test_safe_loader_subclass_is_not_reported(tmp_path: Path) -> None:
    assert _findings(tmp_path, _SAFE_SUBCLASS, "unsafe_deserialization") == []


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\n\nclass L(yaml.Loader):\n    pass\n\ndef f(c):\n    return yaml.load(c, Loader=L)\n",
        "import yaml\n\nclass L(yaml.FullLoader):\n    pass\n\ndef f(c):\n    return yaml.load(c, Loader=L)\n",
        (
            "import yaml\n\nclass L(yaml.SafeLoader):\n    pass\n\n"
            'L.add_multi_constructor("tag:yaml.org,2002:python/object", yaml.constructor.UnsafeConstructor.construct_python_object)\n\n'
            "def f(c):\n    return yaml.load(c, Loader=L)\n"
        ),
        "import yaml\n\ndef f(c):\n    return list(yaml.load_all(c))\n",
        "import yaml\n\ndef f(c):\n    return list(yaml.load_all(c, Loader=yaml.UnsafeLoader))\n",
    ],
    ids=["loader-subclass", "full-loader-subclass", "safe-subclass-with-python-tags", "load-all-default", "load-all-unsafe"],
)
def test_unsafe_loader_is_reported(tmp_path: Path, source: str) -> None:
    assert len(_findings(tmp_path, source, "unsafe_deserialization")) == 1


# ─── Helper chains into subprocess ───────────────────────────────────────────

_TOOL_PREFIX = """
    import subprocess
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("demo")
"""


def test_fixed_program_argv_helper_chain_is_not_reported(tmp_path: Path) -> None:
    source = (
        _TOOL_PREFIX
        + """
    def _kubectl(*args, context=None):
        cmd = ["kubectl", *args]
        if context:
            cmd += ["--context", context]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    def _containers():
        ids = subprocess.run(["docker", "ps", "--format", "{{.ID}}"], capture_output=True, text=True).stdout.split()
        for cid in ids:
            subprocess.run(["docker", "inspect", cid], capture_output=True, text=True)

    def discover():
        _containers()
        return _kubectl("get", "pods", "-o", "json")

    @mcp.tool()
    def graph_export() -> str:
        \"\"\"Export.\"\"\"
        return str(discover())
    """
    )
    assert _findings(tmp_path, source, "interprocedural_dangerous_flow") == []


@pytest.mark.parametrize(
    "sink",
    [
        'subprocess.run("ls " + d, shell=True)',
        'subprocess.run(["sh", "-c", d])',
        'subprocess.run(["/usr/bin/python3", "-c", d])',
        "subprocess.run(command)",
        "os.system(d)",
    ],
    ids=["shell-string", "shell-interpreter-argv", "python-interpreter-argv", "argv-from-elsewhere", "os-system"],
)
def test_shell_or_interpreter_helper_chain_is_reported(tmp_path: Path, sink: str) -> None:
    source = (
        _TOOL_PREFIX
        + f"""
    import os

    def _run(d, command=None):
        return {sink}

    def helper(d):
        return _run(d)

    @mcp.tool()
    def tool(d: str) -> str:
        \"\"\"Run.\"\"\"
        return str(helper("fixed"))
    """
    )
    assert len(_findings(tmp_path, source, "interprocedural_dangerous_flow")) == 1, sink


def test_tool_input_into_fixed_program_argv_is_still_a_taint_finding(tmp_path: Path) -> None:
    source = (
        _TOOL_PREFIX
        + """
    def _clone(url):
        return subprocess.run(["git", "clone", url], check=True)

    @mcp.tool()
    def clone(url: str) -> str:
        \"\"\"Clone.\"\"\"
        return str(_clone(url))
    """
    )
    (tmp_path / "mod.py").write_text(textwrap.dedent(source), encoding="utf-8")
    categories = {finding.category for finding in analyze_project(tmp_path).flow_findings}
    assert "tainted_dangerous_sink" in categories
