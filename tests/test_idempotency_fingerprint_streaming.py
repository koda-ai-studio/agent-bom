"""Fingerprint normalization stays compatible without copying an entire report."""

import gc
import hashlib
import json
import random
import tracemalloc
from datetime import datetime, timezone

import pytest
from pydantic import BaseModel

from agent_bom.api.idempotency_store_core import IdempotencyPayloadError, _normalize_request_payload, idempotency_request_fingerprint


def legacy_fingerprint(payload):
    normalized = _normalize_request_payload(payload or {})
    return hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@pytest.mark.parametrize("seed", range(64))
def test_streaming_normalization_retains_canonical_hashes(seed):
    rng = random.Random(seed)

    def value(depth=0):
        kind = rng.randrange(3) if depth < 4 else 0
        if kind == 1:
            return [value(depth + 1) for _ in range(rng.randrange(5))]
        if kind == 2:
            return {key: value(depth + 1) for key in rng.sample(["idempotency_key", "a", "Ω", 'quote"', "z"], rng.randrange(5))}
        return rng.choice([None, True, False, rng.randrange(-1_000_000, 1_000_000), rng.random(), 'é\n"', ""])

    payload = value()
    assert idempotency_request_fingerprint(payload) == legacy_fingerprint(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {1: "first", "1": "last", "idempotency_key": "ignored", "child": {"idempotency_key": "nested", "value": 3}},
        {"tuple": (True, -0.0, None), "float": float("inf"), "nan": float("nan")},
        {"a": "prefix", "large": "é" * 9000, "z": "suffix"},
        {"when": datetime(2026, 1, 1, tzinfo=timezone.utc), "escaped": '\n"é'},
    ],
)
def test_unusual_keys_and_values_keep_existing_hash_semantics(payload):
    assert idempotency_request_fingerprint(payload) == legacy_fingerprint(payload)


def test_model_serialization_remains_canonical():
    class Payload(BaseModel):
        when: datetime
        entries: list[dict]

    payload = Payload(when=datetime(2026, 1, 1, tzinfo=timezone.utc), entries=[{"idempotency_key": "ignored", "value": 1}])
    assert idempotency_request_fingerprint(payload) == legacy_fingerprint(payload)


def test_cyclic_payload_is_rejected():
    payload = {"nested": {}}
    payload["nested"]["parent"] = payload
    with pytest.raises(IdempotencyPayloadError, match="too deeply nested"):
        idempotency_request_fingerprint(payload)


def test_large_report_normalization_has_bounded_additional_heap():
    payload = {"agents": [{"name": f"agent-{i}", "version": "1.0", "idempotency_key": "ignored"} for i in range(20_000)]}
    expected = legacy_fingerprint(payload)
    gc.collect()
    tracemalloc.start()
    try:
        assert idempotency_request_fingerprint(payload) == expected
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024, f"normalization copied the report: {peak} bytes"
