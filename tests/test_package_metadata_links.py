"""Repository links in package and plugin metadata must point at files that exist."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from tests._tracked_files import tracked_files

ROOT = Path(__file__).resolve().parents[1]
_REPO_LINK = re.compile(r"https://github\.com/koda-ai-studio/agent-bom/(?:blob|tree)/main/([^\s\"')#>?]+)")
_METADATA = re.compile(r"(^|/)(pyproject\.toml|server\.json|plugin\.json|marketplace\.json|glama\.json|smithery\.yaml|PYPI_README\.md)$")


def _metadata_files() -> list[Path]:
    return [ROOT / name for name in tracked_files(ROOT, ".") if _METADATA.search(name) and "node_modules" not in name]


def test_metadata_repository_links_resolve_to_tracked_paths() -> None:
    files = _metadata_files()
    assert any(path.name == "pyproject.toml" for path in files)
    missing = [
        f"{path.relative_to(ROOT)} -> {target}"
        for path in files
        for target in _REPO_LINK.findall(path.read_text(encoding="utf-8"))
        if not (ROOT / target.rstrip("/")).exists()
    ]
    assert missing == []


def test_pyproject_trust_link_points_at_permissions_doc() -> None:
    urls = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["urls"]
    assert urls["Trust & Permissions"].endswith("/blob/main/docs/PERMISSIONS.md")


def test_pypi_keywords_stay_on_the_ai_supply_chain_wedge() -> None:
    keywords = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["keywords"]
    assert 8 <= len(keywords) <= 15
    assert len(set(keywords)) == len(keywords)
    for required in ("ai-bom", "sbom", "mcp", "ai-agents", "supply-chain", "vulnerability-scanner"):
        assert required in keywords
    for off_focus in ("cuda", "pytorch", "openclaw", "ai-enrichment", "cnapp", "gpu-security"):
        assert off_focus not in keywords
