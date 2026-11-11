"""Scan options for self-hosted model-serving endpoint probes."""

from __future__ import annotations

import click

from agent_bom.cloud.serving_runtimes import SERVING_RUNTIMES


def _validate_serving_endpoints(ctx: click.Context, param: click.Parameter, values: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    parsed: list[tuple[str, str]] = []
    for value in values:
        runtime, sep, url = value.partition("=")
        runtime = runtime.strip().lower()
        if not sep or not runtime or not url.strip():
            raise click.BadParameter(f"expected RUNTIME=URL, got {value!r}", ctx=ctx, param=param)
        if runtime not in SERVING_RUNTIMES:
            raise click.BadParameter(
                f"unknown runtime {runtime!r}; choose from {', '.join(sorted(SERVING_RUNTIMES))}", ctx=ctx, param=param
            )
        parsed.append((runtime, url.strip()))
    return tuple(parsed)


def serving_options(fn):
    """``--serving-endpoint RUNTIME=URL`` (repeatable): one endpoint probe per value."""
    return click.option(
        "--serving-endpoint",
        "serving_endpoints",
        multiple=True,
        metavar="RUNTIME=URL",
        callback=_validate_serving_endpoints,
        help=(
            "Probe one self-hosted model-serving endpoint (vllm, tgi, triton, llamacpp, lmstudio). Repeatable. "
            "Records listed models only; bind, TLS, auth and quotas are not collected."
        ),
    )(fn)
