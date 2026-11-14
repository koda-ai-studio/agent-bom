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


#: Scoped, path-like or address-like ids (``project:…``, ARNs, URIs, ``user@host``, dotted names).
_ID_SEPARATORS = re.compile(r"[:/@.]")
#: A generated hash or hex id token, e.g. ``a1157c3d9e``.
_HASH_TOKEN = re.compile(r"^(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{6,}$", re.IGNORECASE)


def is_verbatim_identifier(identifier: str) -> bool:
    """Whether a name is an identifier that must render exactly as recorded, never re-cased."""
    return bool(_ID_SEPARATORS.search(identifier)) or any(_HASH_TOKEN.match(token) for token in re.split(r"[-_]+", identifier))


def format_entity_id(identifier: str) -> str:
    """Canonical formatting of a slug; a name with spaces or an identifier is shown as recorded."""
    trimmed = identifier.strip()
    if not trimmed or re.search(r"\s", trimmed) or is_verbatim_identifier(trimmed):
        return trimmed
    return " ".join(_format_token(token) for token in re.split(r"[-_]+", trimmed) if token)


def agent_display_name(identifier: str, recorded: object = None) -> str:
    recorded_name = recorded.strip() if isinstance(recorded, str) else ""
    return recorded_name or format_entity_id(str(identifier or "")) or "Unknown agent"


def agent_payload_display_name(agent: dict[str, object]) -> str:
    """Display name of a serialized agent row (``name`` + recorded ``enrollment_name``)."""
    return agent_display_name(str(agent.get("name") or ""), agent.get("enrollment_name"))


__all__ = ["agent_display_name", "agent_payload_display_name", "format_entity_id", "is_verbatim_identifier"]
