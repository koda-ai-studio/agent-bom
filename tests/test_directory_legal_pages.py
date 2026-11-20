"""Directory legal links resolve to pages built by MkDocs that say who runs what."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://koda-ai-studio.github.io/agent-bom/"


def test_claude_directory_legal_links_have_real_pages():
    manifest = json.loads((ROOT / "integrations/claude-code/.claude-plugin/plugin.json").read_text(encoding="utf-8"))
    for field, slug in (("privacyPolicyUrl", "privacy"), ("termsOfServiceUrl", "terms")):
        assert manifest[field] == BASE + slug + "/"
        page = (ROOT / "site-docs" / f"{slug}.md").read_text(encoding="utf-8")
        assert "DRAFT" not in page
        assert "offers no public hosted service" in page
        assert f"{slug}.md" in (ROOT / "mkdocs.yml").read_text(encoding="utf-8")


def test_privacy_discloses_storage_and_external_services():
    text = (ROOT / "site-docs/privacy.md").read_text(encoding="utf-8")
    for boundary in ("OSV", "authorization server", "30 minutes", "not a guaranteed deletion deadline", "hosting", "chat history"):
        assert boundary in text


LOOKUP_HOST = "https://agent-bom-lookup.up.railway.app"
LOOKUP_STATUS = "not yet deployed"


def test_lookup_service_is_not_described_as_live_before_it_is_deployed():
    """The lookup URL answered 404 while these pages described it as running.

    The owner checklist in docs/PLUGIN_SUBMISSION.md removes this status only
    after the deployment check passes, together with this test.
    """
    for relative in ("site-docs/privacy.md", "site-docs/terms.md", "integrations/openai-mcp/README.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert LOOKUP_STATUS in text, relative
    for relative in ("site-docs/privacy.md", "site-docs/terms.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert LOOKUP_HOST in text, relative
    checklist = (ROOT / "docs/PLUGIN_SUBMISSION.md").read_text(encoding="utf-8")
    assert f'"{LOOKUP_STATUS}"' in checklist
