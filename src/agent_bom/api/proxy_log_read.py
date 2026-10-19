"""Bounded tenant-scoped reads of local proxy JSONL evidence."""

from __future__ import annotations

from pathlib import Path as _Path

from agent_bom.api.proxy_runtime_projection import _alert_visible_to_tenant
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.security import sanitize_sensitive_payload


def _get_configured_log_path() -> _Path | None:
    """Return the server-configured audit log path, if set.

    The path is set via the AGENT_BOM_LOG environment variable (server-side
    config only — never from user input).  Returns None when the env var is
    unset or the file doesn't exist.
    """
    from agent_bom.core.settings import env_raw

    log_env = env_raw("AGENT_BOM_LOG")
    if not log_env:
        return None
    path = _Path(log_env).resolve()
    if not path.is_file() or path.suffix != ".jsonl":
        return None
    return path


_MAX_EVIDENCE_LOG_LINES = 50_000


_MAX_FEED_LOG_LINES = 1_000


_LOG_TAIL_BLOCK_BYTES = 64 * 1024


def _read_newest_log_lines(path: _Path, *, limit: int) -> list[bytes]:
    """Read at most the newest ``limit`` JSONL lines without scanning the file."""

    if limit < 1:
        return []
    with open(path, "rb") as handle:
        handle.seek(0, 2)
        position = handle.tell()
        chunks: list[bytes] = []
        newline_count = 0
        while position > 0 and newline_count <= limit:
            block_size = min(_LOG_TAIL_BLOCK_BYTES, position)
            position -= block_size
            handle.seek(position)
            chunk = handle.read(block_size)
            chunks.append(chunk)
            newline_count += chunk.count(b"\n")
    data = b"".join(reversed(chunks))
    return data.splitlines()[-limit:]


def _read_alerts_from_log(path: _Path, *, limit: int = _MAX_EVIDENCE_LOG_LINES) -> list[dict]:
    """Read the newest ``limit`` runtime alerts from a JSONL audit log."""
    import json as _json

    alerts: list[dict] = []
    try:
        for raw_line in _read_newest_log_lines(path, limit=limit):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = _json.loads(line)
                if record.get("type") == "runtime_alert":
                    sanitized = sanitize_sensitive_payload(record)
                    if isinstance(sanitized, dict):
                        safe = redact_for_persistence(sanitized, EvidenceTier.SAFE_TO_STORE)
                        if isinstance(safe, dict):
                            alerts.append(safe)
            except (UnicodeDecodeError, ValueError, KeyError):
                continue
    except OSError:
        pass
    return alerts


def _read_metrics_from_log(path: _Path, tenant_id: str = "default") -> dict | None:
    """Read the last proxy_summary record from a JSONL audit log."""
    import json as _json

    last_summary = None
    try:
        with open(path) as f:
            for i, raw_line in enumerate(f):
                if i >= _MAX_EVIDENCE_LOG_LINES:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = _json.loads(line)
                    if record.get("type") == "proxy_summary" and _alert_visible_to_tenant(record, tenant_id):
                        last_summary = record
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
    return last_summary
