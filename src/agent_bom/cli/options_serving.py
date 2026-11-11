"""Scan options for self-hosted model-serving endpoint probes."""

from __future__ import annotations

import click

from agent_bom.cloud.serving_auth import TOKEN_ENV_PREFIX, validate_token_env_name
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


def _validate_token_envs(ctx: click.Context, param: click.Parameter, values: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    parsed: list[tuple[str, str]] = []
    for value in values:
        # The value is never echoed: a mistaken raw token must not reach the terminal.
        url, sep, env_name = value.rpartition("=")
        if not sep or not url.strip():
            raise click.BadParameter("expected URL=ENV_NAME", ctx=ctx, param=param)
        try:
            parsed.append((url.strip(), validate_token_env_name(env_name)))
        except ValueError as exc:
            raise click.BadParameter(str(exc), ctx=ctx, param=param) from None
    return tuple(parsed)


def serving_options(fn):
    """``--serving-endpoint RUNTIME=URL`` (repeatable) and ``--serving-token-env URL=ENV_NAME``."""
    fn = click.option(
        "--serving-token-env",
        "serving_token_envs",
        multiple=True,
        metavar="URL=ENV_NAME",
        callback=_validate_token_envs,
        help=(
            f"Send a bearer token to one --serving-endpoint URL. ENV_NAME must start with {TOKEN_ENV_PREFIX}; "
            "the token is read from ENV_NAME_FILE or ENV_NAME, never from the command line, and is sent only over "
            "https or to loopback. Repeatable."
        ),
    )(fn)
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
