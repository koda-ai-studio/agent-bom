"""Bounded source-reported cloud identifiers, never provider execution receipts."""

from __future__ import annotations

from typing import Any, Mapping

from agent_bom.security import sanitize_text

CLOUD_TRACE_ATTRIBUTES = (
    "cloud.provider",
    "cloud.account.id",
    "cloud.region",
    "cloud.resource_id",
    "faas.invocation_id",
    "faas.version",
    "aws.request_id",
    "rpc.service",
    "rpc.method",
)


def cloud_trace_claims(attributes: Mapping[str, Any], *, account_id: str, provider: str) -> dict[str, Any] | None:
    """Keep exact identifiers or reject them; never truncate an ID into a match."""
    present = {key: attributes[key] for key in CLOUD_TRACE_ATTRIBUTES if key in attributes}
    if not present:
        return None
    safe = {
        key: value
        for key, value in present.items()
        if isinstance(value, str)
        and 0 < len(value) <= 500
        and value == value.strip()
        and sanitize_text(value, max_len=500) == value
        and not any(ord(char) < 32 for char in value)
    }
    conflict = any(
        safe.get(key) and expected and safe[key] != expected
        for key, expected in (("cloud.account.id", account_id), ("cloud.provider", provider))
    )
    resource = safe.get("cloud.resource_id", "")
    if resource.startswith("arn:"):
        parts = resource.split(":", 5)
        conflict |= len(parts) != 6 or any(
            actual and expected and actual != expected
            for actual, expected in (
                ("aws", provider),
                ("aws", safe.get("cloud.provider", "")),
                (parts[4] if len(parts) == 6 else "", account_id),
                (parts[4] if len(parts) == 6 else "", safe.get("cloud.account.id", "")),
                (parts[3] if len(parts) == 6 else "", safe.get("cloud.region", "")),
            )
        )
    state = "invalid" if len(safe) != len(present) else "conflict" if conflict else "consistent"
    return {"basis": "source_reported", "execution_proven": False, "scope_state": state, "attributes": safe}
