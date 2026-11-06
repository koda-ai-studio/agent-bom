"""Field names an AI call record may store: identity, hashes and counts, never prompt or response text."""

AI_CALL_AUDIT_FIELDS: frozenset[str] = frozenset(
    {
        "ai_tenant_id",
        "ai_actor",
        "ai_recorded_at",
        "type",
        "ai_task",
        "ai_provider",
        "ai_model",
        "ai_model_digest",
        "ai_prompt_sha256",
        "ai_response_sha256",
        "ai_prompt_tokens",
        "ai_completion_tokens",
        "ai_latency_ms",
        "ai_outcome",
        "ai_guard_rejected",
        "ai_guard_reason",
    }
)
