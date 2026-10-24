"""Mark caller-facing reads: an API request or an MCP tool call.

The current-estate store refuses unpinned reads inside a boundary while the
demo seed lands. The seed's own writers and the posture precompute read the
same store outside any boundary and are never refused.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_boundary: ContextVar[bool] = ContextVar("current_estate_read_boundary", default=False)


@contextmanager
def estate_read_boundary() -> Iterator[None]:
    token = _boundary.set(True)
    try:
        yield
    finally:
        _boundary.reset(token)


def inside_estate_read_boundary() -> bool:
    return _boundary.get()
