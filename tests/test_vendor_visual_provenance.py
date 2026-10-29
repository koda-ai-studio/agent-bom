"""Official diagram assets stay pinned to first-party sources and exact bytes."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "images" / "vendor" / "provenance.json"

ALLOWED_SOURCE_HOSTS = {
    "cdn.openai.com",
    "arch-center.azureedge.net",
    "openai.com",
    "aws.amazon.com",
    "cloud.google.com",
    "d1.awsstatic.com",
    "learn.microsoft.com",
    "services.google.com",
    "www.anthropic.com",
}

# The manifest carries distinct asset kinds, told apart by which pin they use.
#
# First-party assets come out of a vendor's own downloadable icon archive, so
# their guarantee is the source host: the bytes provably came from the vendor.
#
# Icon-set assets are Simple Icons vectors, which no vendor publishes and whose
# host therefore cannot be first-party. Their guarantee is instead an exact
# upstream commit plus a declared redistributable license — a different pin, not
# a weaker one. Keeping them in the same manifest under one shared byte-hash
# check is what stops either kind from drifting.
FIRST_PARTY_VENDORS = {
    "Amazon Web Services",
    "Anthropic Claude",
    "Google Cloud",
    "Microsoft Azure",
    "OpenAI",
}
ICON_SET_VENDORS = {
    "npm",
    "Go",
    "Rust",
    "NuGet",
    "RubyGems",
    "Packagist",
    "Amazon Web Services",
    "ClickHouse",
    "Databricks",
    "Docker MCP Toolkit",
    "JetBrains AI",
    "Jira",
    "Milvus",
    "Qdrant",
    "Cline",
    "Crusoe",
    "Gemini CLI",
    "Goose",
    "Langfuse",
    "LangSmith",
    "OpenClaw",
    "Roo Code",
    "GitHub",
    "GitHub Copilot",
    "Google Cloud",
    "Hugging Face",
    "Kubernetes",
    "MLflow",
    "Microsoft Azure",
    "Okta",
    "Ollama",
    "Snowflake",
    "Supabase",
    "Vercel",
    "Weights & Biases",
    "Windsurf",
}
REPOSITORY_PINNED_VENDORS = {
    "Cursor",
}
BRAND_REFERENCE_VENDORS = {
    "Google Cloud",
}
ICON_SET_SOURCES = {
    "https://github.com/msaad00/cloud-ai-security-skills": ("https://simpleicons.org", "CC0-1.0"),
    "https://github.com/simple-icons/simple-icons": ("https://simpleicons.org", "CC0-1.0"),
    "https://github.com/lobehub/lobe-icons": ("https://github.com/lobehub/lobe-icons", "MIT"),
}
VENDOR_SVG_HOSTS = {
    "CoreWeave": ("www.coreweave.com", "cdn.prod.website-files.com"),
    "Nebius": ("nebius.com", "nebius.com"),
    "Lambda": ("lambda.ai", "lambda.ai"),
    "RunPod": ("www.runpod.io", None),
    "Vast.ai": ("vast.ai", "vast.ai"),
}
_FULL_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _first_party(assets: list[dict]) -> list[dict]:
    return [asset for asset in assets if "source_archive" in asset]


def _icon_set(assets: list[dict]) -> list[dict]:
    return [
        asset for asset in assets if "source_repo" in asset and "source_page" in asset and asset.get("source_kind") != "brand_reference"
    ]


def _repository_pinned(assets: list[dict]) -> list[dict]:
    return [asset for asset in assets if "source_repo" in asset and "source_page" not in asset]


def _brand_reference(assets: list[dict]) -> list[dict]:
    return [asset for asset in assets if asset.get("source_kind") == "brand_reference"]


def test_vendor_diagram_assets_have_first_party_pinned_provenance() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["neutral_icon_policy"]

    assets = data["assets"]
    first_party = _first_party(assets)
    icon_set = _icon_set(assets)
    repository_pinned = _repository_pinned(assets)
    brand_reference = _brand_reference(assets)
    vendor_svg = [asset for asset in assets if asset.get("source_kind") == "vendor_svg"]

    # Every asset must declare exactly one pin. An entry with neither is
    # unpinned; an entry with both hides which guarantee actually applies.
    for asset in assets:
        assert sum(asset in group for group in (first_party, icon_set, repository_pinned, brand_reference, vendor_svg)) == 1
    assert not [a for a in assets if "source_archive" in a and "source_repo" in a]

    assert {asset["vendor"] for asset in first_party} == FIRST_PARTY_VENDORS
    assert {asset["vendor"] for asset in icon_set} == ICON_SET_VENDORS
    assert {asset["vendor"] for asset in repository_pinned} == (REPOSITORY_PINNED_VENDORS)
    assert {asset["vendor"] for asset in brand_reference} == BRAND_REFERENCE_VENDORS
    assert {asset["vendor"] for asset in vendor_svg} == set(VENDOR_SVG_HOSTS)

    # Shared contract: the bytes on disk are the bytes that were reviewed.
    for asset in assets:
        path = ROOT / asset["path"]
        assert path.is_file(), asset["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == asset["sha256"]
        assert asset["source_path"].endswith(".svg")
        assert asset["terms"]

    for asset in first_party:
        for key in ("source_page", "source_archive"):
            parsed = urlparse(asset[key])
            assert parsed.scheme == "https"
            assert parsed.hostname in ALLOWED_SOURCE_HOSTS

    for asset in icon_set:
        page, license_id = ICON_SET_SOURCES[asset["source_repo"]]
        actual_page, expected_page = urlparse(asset["source_page"]), urlparse(page)
        assert (actual_page.scheme, actual_page.hostname, actual_page.path.rstrip("/")) == (
            expected_page.scheme,
            expected_page.hostname,
            expected_page.path.rstrip("/"),
        )
        assert asset["license"] == license_id

    for asset in vendor_svg:
        page_host, asset_host = VENDOR_SVG_HOSTS[asset["vendor"]]
        page = urlparse(asset["source_page"])
        assert page.scheme == "https" and page.hostname == page_host
        assert asset["retrieved_at"]
        if asset_host:
            source = urlparse(asset["source_path"])
            assert source.scheme == "https" and source.hostname == asset_host
        else:
            assert asset["source_path"] == "footer-logo.svg"
            assert asset["source_selector"] == ".footer-logo svg"

    for asset in brand_reference:
        page = urlparse(asset["source_page"])
        assert page.scheme == "https"
        assert page.hostname == "cloud.google.com"
        assert asset["source_repo"] == "https://github.com/koda-ai-studio/agent-bom"
        assert "source_archive" not in asset

    for asset in icon_set + repository_pinned + brand_reference:
        repo = urlparse(asset["source_repo"])
        assert repo.scheme == "https"
        # A branch or tag can move; only a full commit sha pins the bytes.
        assert _FULL_COMMIT_SHA.match(asset["source_commit"]), asset["path"]
