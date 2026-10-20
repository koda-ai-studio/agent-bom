"""One agent display-name rule for every API, MCP and UI surface.

Mirrors ``ui/lib/display-name.ts``; ``tests/fixtures/contracts/agent_display_names.json``
is the shared case table both sides test against. A recorded name wins;
otherwise the identifier is formatted without inventing words.
"""

from __future__ import annotations

import re

_TOKEN_CASING = {
    "ai": "AI",
    "api": "API",
    "aws": "AWS",
    "cli": "CLI",
    "db": "DB",
    "gcp": "GCP",
    "github": "GitHub",
    "gitlab": "GitLab",
    "iam": "IAM",
    "ide": "IDE",
    "langchain": "LangChain",
    "llamaindex": "LlamaIndex",
    "llm": "LLM",
    "mcp": "MCP",
    "openai": "OpenAI",
    "pii": "PII",
    "postgres": "PostgreSQL",
    "rag": "RAG",
    "s3": "S3",
    "sql": "SQL",
    "ui": "UI",
}


def _format_token(token: str) -> str:
    return _TOKEN_CASING.get(token.lower()) or token[:1].upper() + token[1:]


def format_entity_id(identifier: str) -> str:
    """Canonical formatting of a slug identifier; a name with spaces is already a display name."""
    trimmed = identifier.strip()
    if not trimmed or re.search(r"\s", trimmed):
        return trimmed
    return " ".join(_format_token(token) for token in re.split(r"[-_]+", trimmed) if token)


def agent_display_name(identifier: str, recorded: object = None) -> str:
    recorded_name = recorded.strip() if isinstance(recorded, str) else ""
    return recorded_name or format_entity_id(str(identifier or "")) or "Unknown agent"


def agent_payload_display_name(agent: dict[str, object]) -> str:
    """Display name of a serialized agent row (``name`` + recorded ``enrollment_name``)."""
    return agent_display_name(str(agent.get("name") or ""), agent.get("enrollment_name"))


__all__ = ["agent_display_name", "agent_payload_display_name", "format_entity_id"]
