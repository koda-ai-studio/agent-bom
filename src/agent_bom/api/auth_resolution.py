"""Authentication resolver outcomes and fail-closed pipeline control flow."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

from starlette.responses import Response


@dataclass(frozen=True)
class Resolved:
    """A resolver authenticated a principal; ``response`` is the downstream result.

    The resolver has already applied the per-route authorization/tenant policy
    and dispatched (or produced the terminal authz rejection for) the request.
    """

    response: Response


@dataclass(frozen=True)
class Invalid:
    """A resolver saw a credential it could not accept.

    Terminal: a presented-but-invalid credential is returned as-is and never
    falls through to a later resolver or the anonymous fallback.
    """

    response: Response


@dataclass(frozen=True)
class Absent:
    """No credential this resolver can act on — the pipeline tries the next one."""


Resolution = Resolved | Invalid | Absent


async def run_resolver_chain(resolvers: Iterable[Callable[[], Awaitable[Resolution]]]) -> Response | None:
    """Run an ordered authentication resolver chain: first non-Absent result wins.

    This is the single place that expresses the pipeline's control-flow
    invariant — ``Absent`` continues to the next resolver, while both
    ``Resolved`` and ``Invalid`` are terminal and return their response
    immediately. Returns ``None`` only when every resolver is ``Absent`` (the
    production chain ends in a terminal resolver, so that never happens there;
    it is meaningful for unit tests exercising the loop directly).
    """
    for resolver in resolvers:
        result = await resolver()
        if isinstance(result, Absent):
            continue
        return result.response
    return None
