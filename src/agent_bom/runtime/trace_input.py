"""OTLP JSON scalar normalization shared by tool and model span readers."""

# Explicit orchestration operations must not be counted as model inference.
NON_INFERENCE_OPERATIONS = {
    "execute_tool",
    "invoke_agent",
    "create_agent",
    "invoke_workflow",
    "plan",
    "retrieval",
    "fetch_response",
    "create_memory",
    "create_memory_store",
    "delete_memory",
    "delete_memory_store",
    "search_memory",
    "update_memory",
    "upsert_memory",
}


def duration_ms(span: dict) -> float:
    """Read OTLP JSON uint64 timestamps without losing nanosecond precision."""
    try:
        start = int(span.get("startTimeUnixNano") or 0)
        end = int(span.get("endTimeUnixNano") or 0)
    except (ValueError, TypeError, OverflowError):
        return 0.0
    return (end - start) / 1_000_000 if 0 < start <= end < 2**64 else 0.0
