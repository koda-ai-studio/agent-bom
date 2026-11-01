"""The advertised 10k-package estate must reach /v1/results/push, and a gzip bomb must not.

Measured 2026-11-01 (lane D): a 10k-package CLI report is 154 MB raw and
8.7 MB gzipped (17.7:1). The 64 MiB decoded budget rejected both, so the
largest estate the docs size for could never reach the graph.
"""

from __future__ import annotations

import gzip
import os

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom import config
from agent_bom.api import middleware_body
from agent_bom.api.middleware import MaxBodySizeMiddleware


async def echo(request):  # noqa: ANN001, ANN201
    return JSONResponse({"bytes": len(await request.body())})


def client(limit: int) -> TestClient:
    app = Starlette(routes=[Route("/v1/results/push", echo, methods=["POST"])])
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=64, path_limits={"/v1/results/push": limit})
    return TestClient(app)


def test_defaults_fit_the_advertised_estate_and_compress_by_default() -> None:
    # 154 MB raw at 10k packages (lane D) with headroom for richer findings; still bounded.
    assert config.API_RESULT_PUSH_MAX_BYTES == 256 * 1024 * 1024
    assert config.PUSH_GZIP is True


def test_a_realistic_compression_ratio_is_accepted() -> None:
    # JSON reports compress ~15-20:1; random bytes compress ~1:1. Both are legitimate.
    body = os.urandom(3 * 1024 * 1024)
    with client(8 * 1024 * 1024) as api:
        response = api.post("/v1/results/push", content=gzip.compress(body), headers={"Content-Encoding": "gzip"})
    assert response.status_code == 200
    assert response.json() == {"bytes": len(body)}


def test_a_decompression_bomb_is_refused_before_the_budget_is_exhausted() -> None:
    bomb = gzip.compress(b"\0" * (6 * 1024 * 1024))  # ~6000:1
    assert len(bomb) < 10 * 1024
    with client(8 * 1024 * 1024) as api:
        response = api.post("/v1/results/push", content=bomb, headers={"Content-Encoding": "gzip"})
    assert response.status_code == 413
    detail = response.json()["detail"]
    assert "compression ratio" in detail.lower()
    assert str(middleware_body.MAX_GZIP_EXPANSION_RATIO) in detail


def test_small_highly_compressible_bodies_are_not_mistaken_for_bombs() -> None:
    # A 200 KiB report of repeated keys compresses far beyond the ratio cap; the cap only
    # engages past the warm-up so small honest reports pass.
    body = b'{"agents": []}' * 15_000
    assert len(body) < middleware_body.GZIP_RATIO_WARMUP_BYTES
    with client(8 * 1024 * 1024) as api:
        response = api.post("/v1/results/push", content=gzip.compress(body), headers={"Content-Encoding": "gzip"})
    assert response.status_code == 200


def test_413_says_how_to_split_the_push() -> None:
    with client(256) as api:
        response = api.post("/v1/results/push", content=b"x" * 300)
    assert response.status_code == 413
    detail = response.json()["detail"]
    assert "AGENT_BOM_API_RESULT_PUSH_MAX_BYTES" in detail
    assert "split" in detail.lower()


@pytest.mark.parametrize("compressed", [True, False])
def test_cli_push_honours_the_gzip_setting(monkeypatch: pytest.MonkeyPatch, compressed: bool) -> None:
    monkeypatch.setattr(config, "PUSH_GZIP", compressed)
    from agent_bom.push import _encode_push_payload

    payload, headers = _encode_push_payload({"agents": []})
    assert (headers.get("Content-Encoding") == "gzip") is compressed
    decoded = gzip.decompress(payload) if compressed else payload
    assert decoded == b'{"agents":[]}'
