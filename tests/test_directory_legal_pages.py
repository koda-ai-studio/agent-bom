"""Directory legal links resolve to owner-review drafts built by MkDocs."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://koda-ai-studio.github.io/agent-bom/"


def test_claude_directory_legal_links_have_real_pages():
    manifest = json.loads((ROOT / "integrations/claude-code/.claude-plugin/plugin.json").read_text(encoding="utf-8"))
    for field, slug in (("privacyPolicyUrl", "privacy"), ("termsOfServiceUrl", "terms")):
        assert manifest[field] == BASE + slug + "/"
        page = (ROOT / "site-docs" / f"{slug}.md").read_text(encoding="utf-8")
        assert "Owner review required before publication" in page
        assert "DRAFT" in page
        assert f"{slug}.md" in (ROOT / "mkdocs.yml").read_text(encoding="utf-8")


def test_privacy_discloses_storage_and_external_services():
    text = (ROOT / "site-docs/privacy.md").read_text(encoding="utf-8")
    for boundary in ("OSV", "authorization server", "30 minutes", "not a guaranteed deletion deadline", "hosting", "chat history"):
        assert boundary in text
