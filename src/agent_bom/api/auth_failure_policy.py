"""Fail-closed authentication throttling and bounded failure receipts."""

from __future__ import annotations

import asyncio
import contextvars
import logging
import math
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from agent_bom.api import audit_log, metrics
from agent_bom.api.auth_failure_receipts import RECEIPTS
from agent_bom.api.auth_failure_store import PostgresAuthFailureStore, SQLiteAuthFailureStore
from agent_bom.api.forwarded_identity import (
    UNPARSEABLE_FORWARDED_SOURCE,
    failure_limit_source,
    forwarded_for_header,
    peer_is_trusted_proxy,
    resolve_forwarded_client_ip,
    trusted_proxy_hops,
    trusted_proxy_networks,
)
from agent_bom.api.middleware_limits import RateLimitMiddleware, _build_rate_limit_store
from agent_bom.api.rate_limit_store import PostgresRateLimitStore
from agent_bom.core.settings import env_raw

_AUTH_WORKERS = ThreadPoolExecutor(max_workers=8, thread_name_prefix="auth-state")
# Operations waiting or running. A burst of distinct sources waits briefly for one
# of the eight workers rather than being refused; the deadline still applies.
_MAX_OUTSTANDING = 64
_MAX_SOURCE_OUTSTANDING = 2
# Reads answer every authenticating caller, so failure writes cannot occupy all
# the workers while they wait on a store's write lock.
_MAX_OUTSTANDING_WRITES = 4
_MAX_PENDING_SOURCES = 4096
# Consecutive store errors, with no success between them, that show an outage.
_OUTAGE_FAILURES = 3
_OUTAGE_SECONDS = 5.0
_OUTAGE_PROBE_SECONDS = 0.5


def _positive_setting(name: str, default: int, maximum: int) -> int:
    value = int(env_raw(name) or str(default))
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


class AuthProtectionUnavailableError(RuntimeError):
    """Authentication cannot proceed without its shared protection state."""


class AuthFailurePolicy:
    def __init__(self) -> None:
        self._state_lock = threading.RLock()
        self._outstanding = 0
        self._source_work: dict[str, int] = {}
        self._source_cache: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._source_reads: dict[tuple[asyncio.AbstractEventLoop, str], asyncio.Task[int | None]] = {}
        self._source_waiters: dict[str, int] = {}
        self._proxy_warning_emitted = False
        self._source_warnings: set[str] = set()
        self._unavailable_until = 0.0
        self._next_probe = 0.0
        self._store_failures = 0
        self._outstanding_writes = 0
        self._pending_failures: OrderedDict[str, int] = OrderedDict()
        self.limit = _positive_setting("AGENT_BOM_AUTH_FAILURE_LIMIT", 10, 1000)
        self.base = _positive_setting("AGENT_BOM_AUTH_BACKOFF_SECONDS", 30, 3600)
        self.maximum = _positive_setting("AGENT_BOM_AUTH_MAX_BACKOFF_SECONDS", 900, 3600)
        if self.maximum < self.base:
            raise ValueError("Authentication maximum backoff must be at least its base")
        rate_store = _build_rate_limit_store(60)
        sqlite_path = env_raw("AGENT_BOM_DB")
        auth_path = sqlite_path + ".auth-limits.db" if sqlite_path and sqlite_path != ":memory:" else ":memory:"
        self.store = (
            PostgresAuthFailureStore(rate_store) if isinstance(rate_store, PostgresRateLimitStore) else SQLiteAuthFailureStore(auth_path)
        )
        if env_raw("AGENT_BOM_TRUST_PROXY_AUTH") or env_raw("AGENT_BOM_TRUSTED_PROXY_HOPS") or env_raw("AGENT_BOM_TRUSTED_PROXY_CIDRS"):
            self._warn_ignored_forwarding()

    def _warn_ignored_forwarding(self) -> None:
        if self._proxy_warning_emitted or (trusted_proxy_hops() and trusted_proxy_networks()):
            return
        self._proxy_warning_emitted = True
        logging.getLogger(__name__).warning(
            "Forwarded client addresses are ignored without both AGENT_BOM_TRUSTED_PROXY_CIDRS and "
            "AGENT_BOM_TRUSTED_PROXY_HOPS. Clients behind one proxy share source backoff, including valid credentials."
        )

    def _warn_source_once(self, condition: str, message: str) -> None:
        if condition in self._source_warnings:
            return
        self._source_warnings.add(condition)
        logging.getLogger(__name__).warning(message)

    def _warn_source_conditions(self, request, peer: str, forwarded: str) -> None:
        # Fixed messages only: header values are caller-controlled.
        if not peer:
            self._warn_source_once(
                "no-peer",
                "The API has no transport peer address (a unix socket has none), so forwarded addresses cannot be trusted and "
                "all clients share one authentication failure source. Listen on TCP behind the proxy and set "
                "AGENT_BOM_TRUSTED_PROXY_CIDRS and AGENT_BOM_TRUSTED_PROXY_HOPS.",
            )
        if forwarded:
            self._warn_ignored_forwarding()
            if trusted_proxy_hops() and trusted_proxy_networks() and peer and not peer_is_trusted_proxy(peer):
                self._warn_source_once(
                    "untrusted-peer",
                    "A request carried X-Forwarded-For from a peer outside AGENT_BOM_TRUSTED_PROXY_CIDRS, so the peer address "
                    "was used. If that peer is your proxy, clients behind it share one authentication failure source.",
                )
        elif request.headers.get("x-real-ip"):
            self._warn_source_once(
                "real-ip-only",
                "A request carried X-Real-IP without X-Forwarded-For. X-Real-IP is not used, so clients behind that proxy share "
                "one authentication failure source. Configure the proxy to send X-Forwarded-For and set "
                "AGENT_BOM_TRUSTED_PROXY_CIDRS and AGENT_BOM_TRUSTED_PROXY_HOPS.",
            )

    def _client_address(self, request) -> str:
        client = getattr(request, "client", None)
        peer = client.host if client else ""
        forwarded = forwarded_for_header(request.headers)
        self._warn_source_conditions(request, peer, forwarded)
        address = resolve_forwarded_client_ip(
            peer_host=peer or "unknown", forwarded_for=forwarded, bounded=False, unparseable=UNPARSEABLE_FORWARDED_SOURCE
        )
        if address == UNPARSEABLE_FORWARDED_SOURCE:
            self._warn_source_once(
                "unparseable-forwarded",
                "A trusted X-Forwarded-For entry could not be read as an address. Those requests share one separate "
                "authentication failure source, apart from the proxy's own address. Check what the proxy writes.",
            )
        return address

    def source(self, request) -> str:
        return failure_limit_source(self._client_address(request))

    @staticmethod
    def denied(seconds: int):
        return JSONResponse(
            {"detail": "Authentication attempts temporarily limited for this source"},
            status_code=429,
            headers={"Retry-After": str(seconds), "X-RateLimit-Scope": "auth-source"},
        )

    @staticmethod
    def unavailable():
        return JSONResponse({"detail": "Authentication protection unavailable"}, status_code=503, headers={"Retry-After": "5"})

    def _note_store_success(self) -> None:
        with self._state_lock:
            self._store_failures = 0
            self._unavailable_until = 0.0

    def _note_store_failure(self) -> None:
        with self._state_lock:
            self._source_cache.clear()
            self._store_failures += 1
            if self._store_failures >= _OUTAGE_FAILURES:
                self._unavailable_until = time.monotonic() + _OUTAGE_SECONDS

    def _refused_by_outage(self) -> bool:
        """During an outage, let one operation through at intervals to find recovery."""
        now = time.monotonic()
        with self._state_lock:
            if now >= self._unavailable_until:
                return False
            if now < self._next_probe:
                return True
            self._next_probe = now + _OUTAGE_PROBE_SECONDS
            return False

    async def _call(self, function, *args, admission_source: str = "", write: bool = False, **kwargs):
        if self._refused_by_outage():
            raise AuthProtectionUnavailableError("Authentication state temporarily unavailable")
        source = admission_source or str(args[0] if args else "unknown")
        with self._state_lock:
            if (
                self._outstanding >= _MAX_OUTSTANDING
                or self._source_work.get(source, 0) >= _MAX_SOURCE_OUTSTANDING
                or (write and self._outstanding_writes >= _MAX_OUTSTANDING_WRITES)
            ):
                raise AuthProtectionUnavailableError("Authentication source capacity exhausted")
            self._outstanding += 1
            self._outstanding_writes += int(write)
            self._source_work[source] = self._source_work.get(source, 0) + 1

        def release(completed):
            with self._state_lock:
                self._outstanding -= 1
                self._outstanding_writes -= int(write)
                self._source_work[source] -= 1
                if not self._source_work[source]:
                    del self._source_work[source]
            if completed is not None and not completed.cancelled():
                completed.exception()  # Consume failures after a response timed out.

        try:
            pending = None
            try:
                async with asyncio.timeout(0.5):
                    pending = _AUTH_WORKERS.submit(contextvars.copy_context().run, function, *args, **kwargs)
                    # Release before publishing the result to the request loop:
                    # its next operation must not count this completed work.
                    # This also runs if the request event loop has closed.
                    pending.add_done_callback(release)
                    task = asyncio.wrap_future(pending)
                    # A timed-out request retains its slot until the SQL exits.
                    value = await asyncio.shield(task)
                    self._note_store_success()
                    return value
            except TimeoutError:
                # The deadline bounds waiting for an answer that has not arrived. A
                # stalled host can fire this timer after the store answered, and that
                # answer is still correct, including a block it found.
                if pending is not None and pending.done() and not pending.cancelled() and pending.exception() is None:
                    self._note_store_success()
                    return pending.result()
                # A read still queued has no one waiting for it; do not spend a worker on it.
                if pending is not None:
                    pending.cancel()
                raise
        except TimeoutError as exc:
            # Slow work or local overload is scoped to this request. It cannot
            # trip an outage circuit for unrelated sources.
            raise AuthProtectionUnavailableError("Authentication operation deadline exceeded") from exc
        except Exception as exc:  # broad-except: Any backend failure must close the authentication boundary for this request.
            logging.getLogger(__name__).warning("Authentication state unavailable (%s); failing closed", type(exc).__name__)
            self._note_store_failure()
            raise AuthProtectionUnavailableError("Authentication protection unavailable") from exc
        finally:
            if pending is None:
                release(None)

    async def before(self, request):
        now, source = time.monotonic(), self.source(request)
        # Tasks belong to one event loop. A shared ASGI app may also serve
        # callers on separate loops; keep task ownership local while enforcing
        # worker, waiter and cache bounds across the whole policy instance.
        read_key = (asyncio.get_running_loop(), source)
        with self._state_lock:
            cached = self._source_cache.get(source)
            if cached and cached[0] > now:
                self._source_cache.move_to_end(source)
                remaining = max(0, math.ceil(cached[1] - now))
                return self.denied(remaining) if remaining else None
            if self._source_waiters.get(source, 0) >= 64:
                return self.unavailable()
            task = self._source_reads.get(read_key)
            if task is None:
                if len(self._source_reads) >= _MAX_OUTSTANDING:
                    return self.unavailable()
                task = asyncio.create_task(self._read_source(source))
                self._source_reads[read_key] = task
                task.add_done_callback(lambda _finished: self._release_read(read_key))
            self._source_waiters[source] = self._source_waiters.get(source, 0) + 1
        try:
            result = await asyncio.shield(task)
        finally:
            with self._state_lock:
                self._source_waiters[source] -= 1
                if not self._source_waiters[source]:
                    del self._source_waiters[source]
        if result is None:
            return self.unavailable()
        return self.denied(result) if result else None

    def _release_read(self, read_key: tuple[asyncio.AbstractEventLoop, str]) -> None:
        with self._state_lock:
            self._source_reads.pop(read_key, None)

    async def _read_source(self, source: str) -> int | None:
        try:
            remaining = await self._call(self._current_backoff, source)
        except AuthProtectionUnavailableError:
            return None
        with self._state_lock:
            self._source_cache[source] = (time.monotonic() + 1, time.monotonic() + remaining)
            self._source_cache.move_to_end(source)
            while len(self._source_cache) > 4096:
                self._source_cache.popitem(last=False)
        return remaining

    def _add_pending_failure(self, source: str) -> None:
        with self._state_lock:
            self._pending_failures[source] = self._pending_failures.get(source, 0) + 1
            self._pending_failures.move_to_end(source)
            while len(self._pending_failures) > _MAX_PENDING_SOURCES:
                self._pending_failures.popitem(last=False)
                logging.getLogger(__name__).warning("Discarded an uncounted authentication failure source at the local bound")

    def _write_pending_failures(self, source: str) -> int | None:
        """Write every failure waiting for this source; None when there are none.

        Capacity refusals do not lose an attempt that was already evaluated: its
        count waits here, and the next operation for the source carries it.
        """
        with self._state_lock:
            count = self._pending_failures.pop(source, 0)
        if not count:
            return None
        recorded = False
        try:
            remaining = self.store.record(source, time.time(), limit=self.limit, base=self.base, maximum=self.maximum, count=count)
            recorded = True
            return remaining
        finally:
            if not recorded:
                with self._state_lock:
                    self._pending_failures[source] = self._pending_failures.get(source, 0) + count

    def _current_backoff(self, source: str) -> int:
        recorded = self._write_pending_failures(source)
        return recorded if recorded is not None else self.store.remaining(source, time.time())

    def _submit_receipt(self, request, status_code: int, source: str, now: float, throttled: bool, fingerprint: str | None) -> None:
        credential = request.headers.get("x-api-key") or request.headers.get("authorization") or request.headers.get("cookie") or ""
        fingerprint = fingerprint or (audit_log.fingerprint_auth_credential(credential) if credential else "absent")
        address = self._client_address(request)
        RECEIPTS.submit(
            source,
            now,
            self.store.audit_allowed,
            hmac_sha256=fingerprint,
            status_code=status_code,
            reason_code="auth_source_throttled" if throttled else "authentication_failed",
            **({"client_address": address} if address != source else {}),
        )

    async def record_failed_credential(self, request, status_code: int, fingerprint: str | None = None) -> int:
        """Count a credential that failed verification; returns the source's backoff, if known."""
        metrics.record_auth_failure("failed_credential")
        source, now = self.source(request), time.time()
        with self._state_lock:
            self._source_cache.pop(source, None)
        self._add_pending_failure(source)
        try:
            remaining = await self._call(self._current_backoff, source, write=True)
        except AuthProtectionUnavailableError:
            # The credential was already refused and its count is held for the
            # next operation. Admission, not this answer, fails closed.
            self._submit_receipt(request, status_code, source, now, False, fingerprint)
            return 0
        self._submit_receipt(request, status_code, source, now, bool(remaining), fingerprint)
        return remaining

    async def after(self, request, response):
        # Only the handler that verified a credential can say it failed. A 401
        # also means an expired session, nothing presented, or a missing report
        # token, none of which is a guess at a credential.
        if not (response.status_code in {400, 401, 403} and getattr(request.state, "authentication_failed", False)):
            return response
        fingerprint = getattr(request.state, "auth_credential_fingerprint", None)
        remaining = await self.record_failed_credential(request, response.status_code, fingerprint)
        return self.denied(remaining) if remaining else response


_active_policy: AuthFailurePolicy | None = None
_active_policy_lock = threading.Lock()


def set_active_policy(policy: AuthFailurePolicy) -> None:
    """Share the HTTP middleware's policy, so a block applies on every protocol it serves."""
    global _active_policy
    with _active_policy_lock:
        _active_policy = policy


def active_policy() -> AuthFailurePolicy:
    global _active_policy
    with _active_policy_lock:
        if _active_policy is None:
            _active_policy = AuthFailurePolicy()
        return _active_policy


class AuthFailureMiddleware(BaseHTTPMiddleware):
    """Apply the same authentication boundary to standalone MCP HTTP apps."""

    def __init__(self, app):
        super().__init__(app)
        self.policy = AuthFailurePolicy()

    async def dispatch(self, request, call_next):
        path, method = request.url.path, request.method
        # OAuth discovery is public here: the SDK verifies bearers only on its transport routes.
        if RateLimitMiddleware.needs_no_auth_state(path, method, request.headers) or (
            method in {"GET", "HEAD"} and path.startswith("/.well-known/")
        ):
            return await call_next(request)
        if denied := await self.policy.before(request):
            return denied
        response = await call_next(request)
        # The SDK verifies the bearer behind this boundary and cannot mark the
        # request itself. A challenge without a presented token is not a guess.
        if response.status_code == 401 and (request.headers.get("authorization") or request.headers.get("x-api-key")):
            request.state.authentication_failed = True
        return await self.policy.after(request, response)
