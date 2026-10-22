"""The optional OTEL dependency must reject oversized untrusted trace headers."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize("whitespace", [" ", "\t"])
def test_otel_tracestate_rejects_oversized_headers_within_a_bounded_process(whitespace):
    pytest.importorskip("opentelemetry.trace")
    # An isolated deadline catches the pre-1.45.1 quadratic parser without
    # leaving the pytest worker stuck on attacker-controlled header material.
    subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from opentelemetry.trace import TraceState; "
                "import logging; logging.disable(logging.CRITICAL); "
                f"header = 'vendor=value' + {whitespace!r} * 500_000 + 'x'; "
                "assert len(TraceState.from_header([header])) == 0; "
                "assert TraceState.from_header(['vendor=valid']).get('vendor') == 'valid'"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
