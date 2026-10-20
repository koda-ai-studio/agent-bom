"""The first request after boot must not pay for compiling the route table.

FastAPI builds each included router's effective routes lazily, on the first
request that walks it. Profiled on the demo API, the first ``GET /v1/graph``
spent ~1.9 s of CPU in ``_populate_api_route`` for 213 routes before reaching
the handler. Warming the table at boot moves that cost off the first reader.
"""

from __future__ import annotations

import pytest
from fastapi import APIRouter, FastAPI
from fastapi import routing as fastapi_routing

from agent_bom.api import route_warmup


def _app() -> FastAPI:
    app = FastAPI()
    inner = APIRouter()

    @inner.get("/v1/thing/{item}")
    def thing(item: str) -> dict[str, str]:
        return {"item": item}

    outer = APIRouter()
    outer.include_router(inner)
    app.include_router(outer)
    return app


def _count_builds(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    calls: list[object] = []
    original = fastapi_routing._EffectiveRouteContext.from_api_route

    def spy(*args: object, **kwargs: object) -> object:
        calls.append(kwargs.get("original_route"))
        return original(*args, **kwargs)

    monkeypatch.setattr(fastapi_routing._EffectiveRouteContext, "from_api_route", staticmethod(spy))
    return calls


def test_warm_up_compiles_every_router_before_the_first_request(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    app = _app()
    calls = _count_builds(monkeypatch)
    assert route_warmup.warm_route_tables(app) is True
    built = len(calls)
    assert built >= 1
    with TestClient(app) as client:
        assert client.get("/v1/thing/x").json() == {"item": "x"}
    assert len(calls) == built, "the first request rebuilt routes the warm-up should have compiled"


def test_warm_up_is_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_ROUTE_WARMUP", "0")
    assert route_warmup.start_route_warmup(_app()) is None


def test_warm_up_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken:
        def matches(self, scope: object) -> object:
            raise RuntimeError("boom")

    app = _app()
    app.router.routes.append(Broken())  # type: ignore[arg-type]
    assert route_warmup.warm_route_tables(app) is False
