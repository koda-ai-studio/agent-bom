"""In-process idempotency store used for tests and single-process deployments."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from agent_bom.api.idempotency_store_core import (
    _T,
    IdempotencyConflictError,
    IdempotencyRecord,
    _ensure_request_hash_matches,
    _lease_expiry,
    _reservation_lease_is_expired,
    _utcnow,
)


class InMemoryIdempotencyStore:
    def __init__(self, ttl_hours: int = 24) -> None:
        self._records: dict[tuple[str, str, str, str], IdempotencyRecord] = {}
        self._ttl = timedelta(hours=ttl_hours)
        self._lock = threading.Lock()

    def _prune(self) -> None:
        cutoff = datetime.now(timezone.utc) - self._ttl
        stale = [key for key, record in self._records.items() if datetime.fromisoformat(record.created_at) < cutoff]
        for key in stale:
            self._records.pop(key, None)

    def get(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
    ) -> dict[str, Any] | None:
        with self._lock:
            self._prune()
            record = self._records.get((endpoint, tenant_id, source_id, idempotency_key))
            if record:
                _ensure_request_hash_matches(record.request_hash, request_hash)
            return json.loads(record.response_json) if record else None

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
    ) -> bool:
        with self._lock:
            self._prune()
            key = (endpoint, tenant_id, source_id, idempotency_key)
            existing = self._records.get(key)
            if owner_token and (existing is None or existing.reservation_owner != owner_token):
                return False
            if not owner_token and existing is not None and existing.reservation_owner:
                return False
            if existing is not None:
                _ensure_request_hash_matches(existing.request_hash, request_hash)
            self._records[key] = IdempotencyRecord(
                endpoint=endpoint,
                tenant_id=tenant_id,
                source_id=source_id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_json=json.dumps(response, sort_keys=True),
                created_at=_utcnow(),
                reservation_owner=(
                    "" if response.get("committed") is True else owner_token or (existing.reservation_owner if existing else "")
                ),
                lease_expires_at="",
            )
            return True

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
    ) -> _T:
        """Run durable side effects while the reservation owner is fenced."""

        key = (endpoint, tenant_id, source_id, idempotency_key)
        with self._lock:
            existing = self._records.get(key)
            if existing is None or not owner_token or existing.reservation_owner != owner_token:
                raise IdempotencyConflictError("idempotency reservation ownership was lost")
            _ensure_request_hash_matches(existing.request_hash, request_hash)
            result = action()
            resolved_response = response(result) if callable(response) else response
            self._records[key] = IdempotencyRecord(
                endpoint=endpoint,
                tenant_id=tenant_id,
                source_id=source_id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_json=json.dumps(resolved_response, sort_keys=True),
                created_at=_utcnow(),
            )
            return result

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
    ) -> tuple[dict[str, Any], bool]:
        """Atomically reserve one logical write and return its stable receipt."""
        key = (endpoint, tenant_id, source_id, idempotency_key)
        with self._lock:
            self._prune()
            existing = self._records.get(key)
            if existing is not None:
                _ensure_request_hash_matches(existing.request_hash, request_hash)
                if _reservation_lease_is_expired(
                    existing.response_json,
                    existing.created_at,
                    existing.lease_expires_at,
                    reservation_lease_seconds,
                ):
                    existing.created_at = _utcnow()
                    existing.reservation_owner = owner_token
                    existing.lease_expires_at = _lease_expiry(reservation_lease_seconds)
                    return json.loads(existing.response_json), True
                return json.loads(existing.response_json), False
            self._records[key] = IdempotencyRecord(
                endpoint=endpoint,
                tenant_id=tenant_id,
                source_id=source_id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_json=json.dumps(response, sort_keys=True),
                created_at=_utcnow(),
                reservation_owner=owner_token,
                lease_expires_at=_lease_expiry(reservation_lease_seconds) if owner_token else "",
            )
            return json.loads(json.dumps(response)), True

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
    ) -> bool:
        key = (endpoint, tenant_id, source_id, idempotency_key)
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                return False
            _ensure_request_hash_matches(existing.request_hash, request_hash)
            if not owner_token or existing.reservation_owner != owner_token:
                return False
            existing.lease_expires_at = _lease_expiry(reservation_lease_seconds)
            return True

    def release(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        request_hash: str = "",
        owner_token: str = "",
    ) -> bool:
        key = (endpoint, tenant_id, source_id, idempotency_key)
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                return False
            _ensure_request_hash_matches(existing.request_hash, request_hash)
            if owner_token and existing.reservation_owner != owner_token:
                return False
            self._records.pop(key, None)
            return True
