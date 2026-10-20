"""Prose that mentions bearer tokens is guidance, not a credential."""

import pytest

from agent_bom.security import sanitize_sensitive_payload, sanitize_text

GUIDANCE = (
    "Require OAuth 2.1 (or at minimum a verified bearer token) on the MCP server, or front it "
    "with the agent-bom gateway/proxy and bind authorized agents via bound_agents."
)


@pytest.mark.parametrize("key", ["remediation_guidance", "remediation", "description", None])
def test_bearer_token_guidance_survives_payload_redaction(key):
    payload = {key: GUIDANCE} if key else GUIDANCE
    redacted = sanitize_sensitive_payload(payload)
    assert (redacted[key] if key else redacted) == GUIDANCE


@pytest.mark.parametrize("prose", ["Send a Bearer Token header.", "Use bearer authentication for the API.", "bearer tokens expire"])
def test_bearer_followed_by_a_plain_word_is_kept(prose):
    assert sanitize_text(prose) == prose


@pytest.mark.parametrize(
    "marker",
    ["PLAINMARKER-0001", "plainmarker.value", "marker_value", "Marker42", "plainmarker/abc", "plainmarker=="],
)
def test_bearer_credentials_are_still_redacted(marker):
    for text in (f"Authorization: Bearer {marker}", f"bearer {marker}"):
        assert marker not in str(sanitize_sensitive_payload({"note": text})), text
        assert marker not in sanitize_text(text), text


@pytest.mark.parametrize("marker", ["plainmarker", "Plainmarker"])
def test_a_lowercase_word_that_is_not_bearer_vocabulary_is_still_redacted(marker):
    for text in (f"Authorization: Bearer {marker}", f"bearer {marker}"):
        assert marker not in sanitize_text(text), text
        assert marker not in str(sanitize_sensitive_payload({"note": text})), text


@pytest.mark.parametrize("marker", ["authplainmarker", "tokenplainmarker", "access_plainmarker"])
def test_a_value_that_only_starts_with_bearer_vocabulary_is_still_redacted(marker):
    assert marker not in sanitize_text(f"bearer {marker}")
