"""Shared helpers for CLI option decorator groups."""

from __future__ import annotations


def _apply(decorators):
    """Apply a list of click decorators bottom-up (last in list = outermost)."""

    def wrapper(fn):
        for dec in reversed(decorators):
            fn = dec(fn)
        return fn

    return wrapper


def _single_value(flag: str):
    """Click callback for ``multiple=True`` options that accept one value.

    Click keeps only the last value of a repeated single-valued option. Parsing
    them as ``multiple`` and rejecting a repeat turns that silent drop into a
    usage error.
    """
    import click

    def _cb(_ctx, _param, value):
        if not value:
            return None
        if len(value) > 1:
            raise click.UsageError(f"{flag} accepts only one value; it was given {len(value)} times.")
        return value[0]

    return _cb
