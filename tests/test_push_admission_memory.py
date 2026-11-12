"""Push admission holds one parsed copy of a report, never a model, a dump and the raw body at once."""

from __future__ import annotations

import asyncio
import gc
import json
import tracemalloc
import weakref

import pydantic_core
import pytest
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request

from agent_bom.api.idempotency_store_core import idempotency_request_fingerprint
from agent_bom.api.models import PushPayload
from agent_bom.api.push_ingest_worker import ADMITTED_STATE, admitted_push_result
from agent_bom.api.push_receive import BODY_OWNER_SCOPE_KEY, parse_push_payload


def _report_bytes(agents: int) -> bytes:
    from scripts.generate_graph_benchmark_estate import generate_estate

    report, _ = generate_estate(agents=agents, seed=2145, vulnerable_package_rate=0.08)
    report.update(source_id="  admission-source  ", scan_run={"outcome": "complete"}, custom_extra={"values": [1, 2.5, None]})
    return json.dumps(report).encode()


def _request(raw: bytes, *, owner: Request | None = None) -> Request:
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": raw, "more_body": False}

    scope = {"type": "http", "method": "POST", "path": "/v1/results/push", "headers": [], "query_string": b""}
    if owner is not None:
        scope[BODY_OWNER_SCOPE_KEY] = weakref.ref(owner)
    return Request(scope, receive)


def _parse(raw: bytes, **kwargs) -> PushPayload:
    return asyncio.run(parse_push_payload(_request(raw, **kwargs)))


@pytest.fixture(scope="module")
def report_40() -> bytes:
    return _report_bytes(40)


def test_admission_payload_matches_the_validated_report(report_40):
    reference = PushPayload.model_validate_json(report_40)
    body = _parse(report_40)

    assert body.model_dump(mode="json", exclude_unset=True) == reference.model_dump(mode="json", exclude_unset=True)
    assert body.model_fields_set == reference.model_fields_set
    assert idempotency_request_fingerprint(body) == idempotency_request_fingerprint(reference)
    admitted = admitted_push_result(body)
    assert admitted["pushed"] is True and admitted["ingest_state"] == ADMITTED_STATE
    # The worker re-validates the stored payload: it must rebuild the request's model exactly.
    stored = json.loads(json.dumps(admitted["payload"]))
    assert PushPayload.model_validate(stored) == reference
    assert PushPayload.model_validate(stored).source_id == "admission-source"


def test_a_model_built_without_the_parser_still_admits_its_dump():
    body = PushPayload(source_id="direct", agents=[{"name": "a"}])
    assert admitted_push_result(body)["payload"] == {"source_id": "direct", "agents": [{"name": "a"}]}


def test_admission_keeps_one_parsed_copy_of_the_report(report_40):
    gc.collect()
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        parsed = pydantic_core.from_json(report_40)
        one_copy = tracemalloc.get_traced_memory()[1] - base
        del parsed
        gc.collect()

        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        body = _parse(report_40)
        admitted = admitted_push_result(body)
        admission = tracemalloc.get_traced_memory()[1] - base
        del body, admitted
        gc.collect()

        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        model = PushPayload.model_validate_json(report_40)
        dump = model.model_dump(mode="json", exclude_unset=True)
        model_and_dump = tracemalloc.get_traced_memory()[1] - base
        del model, dump
    finally:
        tracemalloc.stop()
    # A model validated from the parsed report shares it, and the admitted payload is that report.
    assert admission <= one_copy * 1.15 + 256 * 1024, (admission, one_copy)
    assert admission < model_and_dump / 2, (admission, model_and_dump)


@pytest.mark.parametrize(
    "raw",
    [b"{bad json", b"", b"[1, 2]", b'{"source_id": 5}', b'{"agents": "nope"}', b'{"x": NaN, "scan_run": {"warning_count": 1.5}}'],
)
def test_validation_errors_keep_the_json_validator_shape(raw):
    try:
        PushPayload.model_validate_json(raw or b"{}")
        expected = None
    except pydantic_core.ValidationError as exc:
        expected = [{**error, "loc": ("body", *error["loc"])} for error in exc.errors(include_url=False)]
    if expected is None:
        assert isinstance(_parse(raw), PushPayload)
        return
    with pytest.raises(RequestValidationError) as caught:
        _parse(raw)
    assert list(caught.value.errors()) == expected


def test_the_buffered_request_body_is_released_once_validated(report_40):
    owner = _request(report_40)
    owner._body = report_40  # what the body-size middleware leaves on its own request
    request = _request(report_40, owner=owner)

    async def run():
        body = await parse_push_payload(request)
        return body, "_body" in request.__dict__, "_body" in owner.__dict__

    body, route_holds, middleware_holds = asyncio.run(run())
    assert body.source_id == "admission-source"
    assert not route_holds and not middleware_holds
