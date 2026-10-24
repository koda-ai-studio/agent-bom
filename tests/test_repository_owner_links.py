"""Shipped links must point at the repository's current home.

The project moved from ``msaad00/agent-bom`` to ``koda-ai-studio/agent-bom``.
A few references stay on the old owner on purpose: verifiers that must still
accept releases signed before the transfer, detectors for stale published
text, the legacy MCP Registry listing note, and identifiers baked into
already-issued attestations or the Go module path. Everything else repoints.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests._tracked_files import tracked_files

ROOT = Path(__file__).resolve().parents[1]

SCOPES = (
    "src",
    "ui/app",
    "ui/components",
    "ui/lib",
    "ui/scripts",
    "integrations",
    "docs",
    "site-docs",
    "deploy",
    "examples",
    "scripts",
    ".github",
    "sdks",
    "config",
    "README.md",
    "SUPPORT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "Dockerfile",
    "action.yml",
    "Makefile",
    ".pre-commit-hooks.yaml",
)
EXCLUDED_PARTS = ("src/agent_bom/ui_dist/", "node_modules/")

OLD_REPO_REFERENCE = re.compile(r"(?:github\.com/|githubusercontent\.com/|repos/|--repo |uses:\s*|io\.github\.)msaad00/agent-bom")

# Each marker names a line that keeps the old owner deliberately.
DELIBERATELY_OLD_MARKERS = (
    "msaad00|koda-ai-studio",  # verifiers accepting both owners
    "koda-ai-studio|msaad00",
    "msaad00/agent-bom@v0.88.4",  # stale-published-text detectors
    r"msaad00/agent-bom@v0\.88\.4",
    'r"uses:\\s*msaad00/agent-bom@v([0-9]',  # Glama listing still renders the old ref
    "former `io.github.msaad00/agent-bom` listing",  # legacy MCP Registry identity
    "_BUILDER_ID = ",  # identity inside already-issued attestations
    "msaad00/agent-bom/sdks/go",  # Go module path, declared in sdks/go/go.mod
    "msaad00/agent-bom/examples/go-sdk",
)

CURRENT_TREE_LINK = re.compile(
    r"(?:github\.com/koda-ai-studio/agent-bom/(?:blob|tree)/main|raw\.githubusercontent\.com/koda-ai-studio/agent-bom/main)/"
    r"([^\s\"'`)<>#?\]]+)"
)


def _shipped_files() -> list[Path]:
    files = []
    for rel in tracked_files(ROOT, *SCOPES):
        if not rel or any(part in rel for part in EXCLUDED_PARTS):
            continue
        path = ROOT / rel
        if path.is_file():
            files.append(path)
    return files


def _text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def test_shipped_links_use_the_current_repository_owner() -> None:
    stale: list[str] = []
    for path in _shipped_files():
        text = _text(path)
        if text is None or "msaad00" not in text:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if OLD_REPO_REFERENCE.search(line) and not any(marker in line for marker in DELIBERATELY_OLD_MARKERS):
                stale.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:160]}")
    assert stale == [], "links still point at the old repository owner:\n" + "\n".join(stale)


def test_current_repository_tree_links_name_files_that_exist() -> None:
    missing: list[str] = []
    for path in _shipped_files():
        text = _text(path)
        if text is None or "koda-ai-studio/agent-bom/" not in text:
            continue
        for match in CURRENT_TREE_LINK.finditer(text):
            target = match.group(1).rstrip(".,;:")
            if not (ROOT / target).exists():
                missing.append(f"{path.relative_to(ROOT)}: {target}")
    assert missing == [], "links name files that do not exist on main:\n" + "\n".join(sorted(set(missing)))


def _load_script(name: str, root: Path = ROOT):
    import importlib.util
    import sys

    path = root / "scripts" / name
    mod_name = f"_owner_links_{name.removesuffix('.py').replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


def test_release_bump_rewrites_openclaw_image_pins_under_the_current_owner() -> None:
    bump = _load_script("bump-version.py")
    text = "docker: ghcr.io/koda-ai-studio/agent-bom:0.1.0\nlegacy: ghcr.io/msaad00/agent-bom:0.1.0\n"
    for _glob, pattern, template in bump.OPENCLAW_SKILL_PATTERNS:
        text = pattern.sub(template.format(v="9.9.9"), text)
    assert "ghcr.io/koda-ai-studio/agent-bom:9.9.9" in text
    assert "ghcr.io/msaad00/agent-bom:9.9.9" in text


def test_release_consistency_sees_openclaw_image_pins_under_either_owner() -> None:
    crc = _load_script("check_release_consistency.py")
    text = "ghcr.io/koda-ai-studio/agent-bom:1.2.3 ghcr.io/msaad00/agent-bom:1.2.2"
    assert set(crc.OPENCLAW_DOCKER_PIN.findall(text)) == {"1.2.3", "1.2.2"}


def test_release_wheel_verifier_reads_action_pins_under_either_owner() -> None:
    verifier = _load_script("verify_release_wheel.py")
    text = "uses: koda-ai-studio/agent-bom@v1.2.3 uses: msaad00/agent-bom@v1.2.2"
    assert set(verifier.INSTALL_PIN.findall(text)) == {"1.2.3", "1.2.2"}


def test_glama_listing_version_prefers_the_action_ref_under_the_current_owner() -> None:
    glama = _load_script("check_glama_listing.py")
    page = "Changelog v9.9.9 and usage: uses: koda-ai-studio/agent-bom@v1.2.3"
    assert glama._extract_listing_version(page) == "1.2.3"
