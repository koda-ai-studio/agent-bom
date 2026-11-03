"""Shared idempotency primitives: records, errors, the store protocol and lease math.

Backend-neutral pieces of :mod:`agent_bom.api.idempotency_store`. The SQLite
and Postgres stores stay in that module; this one holds everything they share.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Protocol, TypeVar

_T = TypeVar("_T")
_FINGERPRINT_BUFFER_BYTES = 2048


@dataclass
class IdempotencyRecord:
    endpoint: str
    tenant_id: str
    source_id: str
    idempotency_key: str
    request_hash: str
    response_json: str
    created_at: str
    reservation_owner: str = ""
    lease_expires_at: str = ""


class IdempotencyConflictError(RuntimeError):
    """Raised when a key is reused for a different request payload."""


class IdempotencyPayloadError(ValueError):
    """Raised when a request payload cannot be fingerprinted.

    Pydantic's serializer aborts with ``ValueError: Circular reference detected
    (depth exceeded)`` on a deeply nested body, and ``json.dumps`` can hit the
    interpreter recursion limit on the same input. Both are caller-controlled,
    so they must land as a 422 instead of escaping as an unhandled 500.
    """


class IdempotencyReservationHeartbeat:
    """Keep a reservation live and expose owner loss before durable commit."""

    def __init__(
        self,
        store: IdempotencyStore,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str,
        owner_token: str,
        lease_seconds: int,
    ) -> None:
        self._store = store
        self._args = (endpoint, tenant_id, source_id, idempotency_key)
        self._request_hash = request_hash
        self._owner_token = owner_token
        self._lease_seconds = lease_seconds
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    def ensure_owned(self) -> None:
        owned = self._store.heartbeat(
            *self._args,
            request_hash=self._request_hash,
            owner_token=self._owner_token,
            reservation_lease_seconds=self._lease_seconds,
        )
        if not owned:
            self._lost.set()
            raise IdempotencyConflictError("idempotency reservation ownership was lost")

    def __enter__(self) -> IdempotencyReservationHeartbeat:
        def beat() -> None:
            interval = max(0.25, self._lease_seconds / 3)
            while not self._stop.wait(interval):
                try:
                    self.ensure_owned()
                except Exception:  # noqa: BLE001 - ownership loss is observed by the request thread
                    self._lost.set()
                    return

        self._thread = threading.Thread(target=beat, name="idempotency-reservation-heartbeat", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: object = None, *_args: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        if exc_type is not None:
            self._store.release(
                *self._args,
                request_hash=self._request_hash,
                owner_token=self._owner_token,
            )


def idempotency_owner_token() -> str:
    return uuid.uuid4().hex


class IdempotencyStore(Protocol):
    def get(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
    ) -> dict[str, Any] | None: ...
    def put(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
        owner_token: str = "",
    ) -> bool: ...
    def claim(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any],
        *,
        request_hash: str = "",
        reservation_lease_seconds: int | None = None,
        owner_token: str = "",
    ) -> tuple[dict[str, Any], bool]: ...
    def heartbeat(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str,
        owner_token: str,
        reservation_lease_seconds: int,
    ) -> bool: ...
    def release(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
        owner_token: str = "",
    ) -> bool: ...
    def commit_claim(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        response: dict[str, Any] | Callable[[_T], dict[str, Any]],
        *,
        action: Callable[[], _T],
        request_hash: str,
        owner_token: str,
    ) -> _T: ...


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reservation_is_expired(response_json: str, created_at: str, lease_seconds: int | None) -> bool:
    """Return whether an explicitly uncommitted reservation can be reclaimed."""

    if lease_seconds is None:
        return False
    try:
        response = json.loads(response_json)
        created = datetime.fromisoformat(created_at)
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(response, dict) or response.get("committed") is not False:
        return False
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(1, int(lease_seconds)))
    return created <= cutoff


def _lease_expiry(lease_seconds: int | None) -> str:
    if lease_seconds is None:
        return ""
    return (datetime.now(timezone.utc) + timedelta(seconds=max(1, int(lease_seconds)))).isoformat()


def _reservation_lease_is_expired(
    response_json: str,
    created_at: str,
    lease_expires_at: str,
    lease_seconds: int | None,
) -> bool:
    if lease_seconds is None:
        return False
    try:
        response = json.loads(response_json)
    except json.JSONDecodeError:
        return False
    if not isinstance(response, dict) or response.get("committed") is not False:
        return False
    if lease_expires_at:
        try:
            expires = datetime.fromisoformat(lease_expires_at)
        except ValueError:
            return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires <= datetime.now(timezone.utc)
    return _reservation_is_expired(response_json, created_at, lease_seconds)


def _normalize_request_payload(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        return {
            str(key): _normalize_request_payload(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) != "idempotency_key"
        }
    if isinstance(value, list | tuple):
        return [_normalize_request_payload(item) for item in value]
    return value


def _request_json_chunks(value: Any, encoder: json.JSONEncoder) -> Iterator[str]:
    """Normalize one container at a time, retaining the existing canonical bytes."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        # Preserve string-key collision order and recursive key exclusion. Only
        # this container's references are copied; descendants stay untouched.
        items = {str(key): item for key, item in sorted(value.items(), key=lambda pair: str(pair[0])) if str(key) != "idempotency_key"}
        yield "{"
        for index, (key, item) in enumerate(items.items()):
            if index:
                yield ","
            yield encoder.encode(key)
            yield ":"
            yield from _request_json_chunks(item, encoder)
        yield "}"
    elif isinstance(value, list | tuple):
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from _request_json_chunks(item, encoder)
        yield "]"
    else:
        yield encoder.encode(value)


def idempotency_request_fingerprint(payload: Any) -> str:
    """Return a stable fingerprint for comparing idempotent write retries.

    Raises:
        IdempotencyPayloadError: when the caller's payload is too deeply nested
            (or otherwise cyclic) to normalize. Callers surface this as 422.
    """
    try:
        # The one-shot C encoder holds the GIL for the entire report, even
        # when this function runs in a worker thread. Incremental encoding
        # and normalization keep the same canonical bytes without an extra
        # full tree of containers whose collection can stall other requests.
        digest = hashlib.sha256()
        encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), default=str)
        pending = bytearray()
        for chunk in _request_json_chunks(payload or {}, encoder):
            encoded = chunk.encode("utf-8")
            if len(encoded) >= _FINGERPRINT_BUFFER_BYTES:
                if pending:
                    digest.update(pending)
                    pending.clear()
                digest.update(encoded)
                time.sleep(0)
            else:
                pending.extend(encoded)
                if len(pending) >= _FINGERPRINT_BUFFER_BYTES:
                    # hashlib releases the GIL above 2047 bytes. Tiny token
                    # updates otherwise keep competing with the API loop.
                    digest.update(pending)
                    pending.clear()
                    # Give runnable request threads a turn; repeated tiny
                    # Python tokens can otherwise reclaim the GIL immediately.
                    time.sleep(0)
        if pending:
            digest.update(pending)
    except (ValueError, TypeError, RecursionError) as exc:
        raise IdempotencyPayloadError("Request payload is too deeply nested to process") from exc
    return digest.hexdigest()


def _ensure_request_hash_matches(stored_hash: str, request_hash: str) -> None:
    if stored_hash and request_hash and stored_hash != request_hash:
        raise IdempotencyConflictError("Idempotency key was reused with a different request payload")
