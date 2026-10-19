"""Request traces retain failures without exporting exception secrets."""

import sys
from contextlib import nullcontext
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest
from starlette.applications import Starlette
from starlette.requests import Request

from agent_bom.api import middleware_headers as middleware


@pytest.mark.asyncio
@pytest.mark.parametrize("chained", [False, True])
async def test_request_failure_trace_omits_raw_exception_and_automatic_recording(monkeypatch, chained):
    # The optional SDK is not required for the default suite. Exercise the
    # production middleware at the tracer boundary, including context options.
    span = Mock()
    tracer = Mock()
    tracer.start_as_current_span.return_value = nullcontext(span)
    trace = ModuleType("opentelemetry.trace")
    trace.get_tracer = Mock(return_value=tracer)
    trace.StatusCode = SimpleNamespace(ERROR="ERROR")
    trace.Status = lambda code, description: SimpleNamespace(status_code=code, description=description)
    package = ModuleType("opentelemetry")
    package.trace = trace
    monkeypatch.setitem(sys.modules, "opentelemetry", package)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace)
    monkeypatch.setattr(middleware, "configure_otel_tracing", lambda: True)
    request = Request(
        {"type": "http", "method": "GET", "path": "/v1/jobs", "query_string": b"", "headers": [(b"x-request-id", b"trace-redaction-test")]}
    )
    failure = RuntimeError("password=SYNTHETIC_PASSWORD /private/SYNTHETIC_PATH")
    if chained:
        failure.__cause__ = ValueError("token=SYNTHETIC_CAUSE")

    async def fail(_request):
        raise failure

    with pytest.raises(RuntimeError) as caught:
        await middleware.TrustHeadersMiddleware(Starlette()).dispatch(request, fail)
    assert caught.value is failure  # tracing must not swallow or replace failures
    exported = repr(span.mock_calls)
    for marker in ("SYNTHETIC_PASSWORD", "SYNTHETIC_PATH", "SYNTHETIC_CAUSE"):
        assert marker not in exported
    options = tracer.start_as_current_span.call_args.kwargs
    assert options["record_exception"] is False
    assert options["set_status_on_exception"] is False
    span.record_exception.assert_not_called()
    event_name, attributes = span.add_event.call_args.args
    assert event_name == "exception"
    assert attributes["exception.type"] == "RuntimeError"
    assert attributes["exception.escaped"] is True
    assert span.set_status.call_args.args[0].status_code == "ERROR"
    assert ("agent_bom.request_id", "trace-redaction-test") in [call.args for call in span.set_attribute.call_args_list]
