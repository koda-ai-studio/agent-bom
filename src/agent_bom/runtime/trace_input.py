"""OTLP JSON scalar normalization shared by tool and model span readers."""


def duration_ms(span: dict) -> float:
    """Read OTLP JSON uint64 timestamps without losing nanosecond precision."""
    try:
        start = int(span.get("startTimeUnixNano") or 0)
        end = int(span.get("endTimeUnixNano") or 0)
    except (ValueError, TypeError, OverflowError):
        return 0.0
    return (end - start) / 1_000_000 if 0 < start <= end < 2**64 else 0.0
