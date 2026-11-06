"""The CLI's durable AI call record, in the JSONL chain format `agent-bom runtime audit --verify-chain` reads.

Hashes and counts only, the same fields the control plane writes to its audit
table. The chain continues across processes: each append reads the head under an
exclusive lock. Set AGENT_BOM_AI_LOCAL_AUDIT=0 to opt out.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from agent_bom.ai_components.call_audit import AICallRecord, register_ai_call_sink
from agent_bom.audit_integrity import compute_audit_record_hash, persist_ephemeral_chain_key, resolve_verifier_chain_keys
from agent_bom.core.settings import env_bool
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.security import sanitize_sensitive_payload
from agent_bom.storage import state_home

try:
    import fcntl
except ImportError:  # Windows: appends still chain within one process.
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger("agent_bom.ai_enrich")
_ALGORITHM = "aes-cmac-128"
_registered = False
_lock = threading.Lock()


def local_ai_audit_path() -> Path:
    return state_home.state_path("ai-audit", "ai-calls.jsonl")


def _head(handle: IO[str]) -> str:
    """The chain head is the last record on disk, so another process's append is never forked over."""
    handle.seek(0)
    last = ""
    for line in handle:
        if line.strip():
            last = line
    if not last:
        return ""
    try:
        return str(json.loads(last).get("record_hash", ""))
    except ValueError:
        return ""


def _append(record: AICallRecord, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("local AI audit path must not be a symlink")
    created = not path.exists()
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "r+") as handle:
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        if created or not state_home_sidecar(path).exists():
            persist_ephemeral_chain_key(path, os.urandom(32))
        key = resolve_verifier_chain_keys(path)[0]
        details = record.to_details()
        details["tenant_id"] = details["tenant_id"] or "local"
        details["actor"] = details["actor"] or "cli"
        sanitized = sanitize_sensitive_payload({f"ai_{name}": value for name, value in details.items()})
        payload: dict[str, Any] = redact_for_persistence(sanitized, EvidenceTier.SAFE_TO_STORE)
        payload["type"] = "ai_call"
        payload["ai_recorded_at"] = datetime.now(timezone.utc).isoformat()
        payload["record_hash_algorithm"] = _ALGORITHM
        prev_hash = _head(handle)
        record_hash = compute_audit_record_hash(payload, prev_hash, _ALGORITHM, key=key)
        handle.seek(0, os.SEEK_END)
        handle.write(json.dumps({**payload, "prev_hash": prev_hash, "record_hash": record_hash}, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def state_home_sidecar(path: Path) -> Path:
    return Path(f"{path}.chain-key")


def append_local_ai_call(record: AICallRecord) -> None:
    _append(record, local_ai_audit_path())


def local_ai_call_sink(record: AICallRecord) -> None:
    """A CLI user keeps their scan and their advice if the file cannot be written; they are told, and the report says so."""
    try:
        _append(record, local_ai_audit_path())
    except (OSError, ValueError, TypeError) as exc:
        logger.warning("local AI audit write failed: %s", type(exc).__name__)


def ensure_local_ai_audit() -> bool:
    """Start recording this process's AI calls. Returns False when the operator opted out."""
    global _registered
    if not env_bool("AGENT_BOM_AI_LOCAL_AUDIT", True, on_invalid="default"):
        return False
    with _lock:
        if not _registered:
            register_ai_call_sink(local_ai_call_sink)
            _registered = True
    return True
