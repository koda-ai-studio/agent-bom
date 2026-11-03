"""The API-key verify cache skips repeat scrypt work without weakening any key check."""

from __future__ import annotations

import statistics
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom import config
from agent_bom.api import api_key_record, api_key_verify_cache, auth
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    monkeypatch.setattr(config, "API_KEY_VERIFY_CACHE_TTL_SECONDS", 60.0)
    monkeypatch.setattr(config, "API_KEY_VERIFY_CACHE_MAX_ENTRIES", 1024)
    api_key_verify_cache.clear()
    yield
    api_key_verify_cache.clear()


@pytest.fixture()
def derivations(monkeypatch):
    calls: list[str] = []
    real = api_key_record._derive_key

    def counting(raw_key: str, salt: bytes) -> str:
        calls.append(salt.hex())
        return real(raw_key, salt)

    monkeypatch.setattr(api_key_record, "_derive_key", counting)
    return calls


def _store_with_key(**kwargs):
    store = auth.KeyStore()
    raw, key = auth.create_api_key("ci", auth.Role.ANALYST, tenant_id="tenant-a", **kwargs)
    store.add(key)
    return store, raw, key


def test_second_verify_skips_scrypt(derivations):
    store, raw, key = _store_with_key()
    first = store.verify(raw)
    second = store.verify(raw)
    assert first is key and second is key
    assert len(derivations) == 1


def test_cached_identity_matches_uncached(derivations, monkeypatch):
    store, raw, _ = _store_with_key()
    cached = (store.verify(raw), store.verify(raw))
    monkeypatch.setattr(config, "API_KEY_VERIFY_CACHE_TTL_SECONDS", 0.0)
    uncached = store.verify(raw)
    for result in cached:
        assert result is not None and uncached is not None
        assert (result.key_id, result.tenant_id, result.role, result.scopes) == (
            uncached.key_id,
            uncached.tenant_id,
            uncached.role,
            uncached.scopes,
        )
    assert len(derivations) == 2


def test_revoke_takes_effect_on_the_next_verify(derivations):
    store, raw, key = _store_with_key()
    assert store.verify(raw) is key
    assert store.remove(key.key_id)
    assert store.verify(raw) is None
    assert api_key_verify_cache.size() == 0


def test_rotation_past_overlap_rejects_a_cached_key(derivations):
    store, raw, key = _store_with_key()
    assert store.verify(raw) is key
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    assert store.mark_rotating(key.key_id, replacement_key_id="replacement", overlap_until=past)
    assert store.verify(raw) is None


def test_deleted_key_is_not_served_from_cache(derivations):
    store, raw, key = _store_with_key()
    assert store.verify(raw) is key
    assert store.delete_tenant("tenant-a") == 1
    assert store.verify(raw) is None


def test_key_expiry_is_honoured_while_cached(derivations, monkeypatch):
    store, raw, key = _store_with_key()
    assert store.verify(raw) is key
    key.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    assert store.verify(raw) is None


def test_entry_never_outlives_the_key_expiry(derivations, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(api_key_verify_cache, "_now", lambda: clock[0])
    store, raw, key = _store_with_key()
    key.expires_at = (datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat()
    assert store.verify(raw) is key
    clock[0] += 6
    store.verify(raw)
    assert len(derivations) == 2


def test_ttl_expiry_re_derives(derivations, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(api_key_verify_cache, "_now", lambda: clock[0])
    monkeypatch.setattr(config, "API_KEY_VERIFY_CACHE_TTL_SECONDS", 10.0)
    store, raw, key = _store_with_key()
    assert store.verify(raw) is key
    clock[0] += 9
    assert store.verify(raw) is key
    assert len(derivations) == 1
    clock[0] += 2
    assert store.verify(raw) is key
    assert len(derivations) == 2


def test_ttl_is_capped_at_sixty_seconds(derivations, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(api_key_verify_cache, "_now", lambda: clock[0])
    monkeypatch.setattr(config, "API_KEY_VERIFY_CACHE_TTL_SECONDS", 3600.0)
    store, raw, _ = _store_with_key()
    store.verify(raw)
    clock[0] += 61
    store.verify(raw)
    assert len(derivations) == 2


def test_wrong_key_is_never_cached_or_served(derivations):
    store, raw, key = _store_with_key()
    assert store.verify(raw) is key
    wrong = raw[:12] + ("x" if raw[12] != "x" else "y") + raw[13:]
    assert store.verify(wrong) is None
    assert store.verify(wrong) is None
    assert len(derivations) == 3
    assert api_key_verify_cache.size() == 1


def test_cache_holds_no_raw_key_or_derived_hash(derivations):
    store, raw, key = _store_with_key()
    store.verify(raw)
    dumped = repr(api_key_verify_cache._entries)
    assert raw not in dumped
    assert key.key_hash not in dumped
    assert bytes.fromhex(key.key_hash) not in api_key_verify_cache._entries
    assert all(bytes.fromhex(key.key_hash) not in (k, v.fingerprint) for k, v in api_key_verify_cache._entries.items())


def test_replaced_hash_for_same_key_id_is_not_served(derivations):
    store, raw, key = _store_with_key()
    assert store.verify(raw) is key
    key.key_salt = "00" * 16
    assert store.verify(raw) is None


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(config, "API_KEY_VERIFY_CACHE_MAX_ENTRIES", 3)
    store = auth.KeyStore()
    raws = []
    for index in range(5):
        raw, key = auth.create_api_key(f"k{index}", auth.Role.VIEWER, tenant_id="tenant-a")
        store.add(key)
        raws.append(raw)
    for raw in raws:
        assert store.verify(raw) is not None
    assert api_key_verify_cache.size() == 3


def test_zero_ttl_disables_the_cache(derivations, monkeypatch):
    monkeypatch.setattr(config, "API_KEY_VERIFY_CACHE_TTL_SECONDS", 0.0)
    store, raw, _ = _store_with_key()
    store.verify(raw)
    store.verify(raw)
    assert len(derivations) == 2
    assert api_key_verify_cache.size() == 0


def _ping_app(*, with_auth: bool) -> FastAPI:
    app = FastAPI()

    @app.get("/v1/fleet")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    if with_auth:
        app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
        app.add_middleware(TrustHeadersMiddleware)
    return app


def test_authenticated_request_overhead_budget(monkeypatch):
    """Median auth overhead stays under 10 ms once the key has been verified once.

    Requests to the authenticated and the bare app are interleaved so machine
    load lands on both samples equally; the median discards scheduler spikes.
    An uncached scrypt verify alone costs tens of milliseconds, so this budget
    fails without the cache and has wide headroom with it.
    """
    store, raw, _ = _store_with_key()
    monkeypatch.setattr(auth, "_key_store", store)
    authed = TestClient(_ping_app(with_auth=True), headers={"Authorization": f"Bearer {raw}"})
    bare = TestClient(_ping_app(with_auth=False))
    for _ in range(5):
        assert authed.get("/v1/fleet").status_code == 200
        assert bare.get("/v1/fleet").status_code == 200
    deltas = []
    for _ in range(40):
        started = time.perf_counter()
        assert authed.get("/v1/fleet").status_code == 200
        authed_ms = (time.perf_counter() - started) * 1000
        started = time.perf_counter()
        assert bare.get("/v1/fleet").status_code == 200
        bare_ms = (time.perf_counter() - started) * 1000
        deltas.append(authed_ms - bare_ms)
    assert statistics.median(deltas) <= 10.0, f"median auth overhead {statistics.median(deltas):.1f} ms"
