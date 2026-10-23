"""Strict-body contract for write routes that take a raw ``dict`` body.

Most write routes bind a Pydantic model, so an unknown key is rejected by
``model_config = ConfigDict(extra="forbid")`` and a wrong type is rejected by
the field annotation. A minority take ``body: dict`` and hand-validate, which
loses both guarantees: an unknown key was silently dropped, and a wrong type
was silently *coerced* — ``{"agent_id": {"x": 1}}`` issued an identity literally
named ``"{'x': 1}"``.

That is the same defect the MCP layer fixed in ``agent_bom.mcp_strict_args``:
extra properties were accepted and dropped, so a typo'd argument produced a
confident wrong answer. The remedy here is the same one, and the error message
follows the same shape — name the offending key, then list what is accepted.

These helpers raise 400, matching the status the hand-validating routes already
return for every other body complaint, so one route never answers a bad body
two different ways.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated

from fastapi import HTTPException, Query, Request

__all__ = ["PageLimit1000", "reject_unknown_fields", "reject_unknown_query_params", "require_scalar_str"]

# Query-string half of the contract: a list route's page size is bounded so an
# oversized request is a visible 422 (and an OpenAPI maximum), never a silent
# clamp or an unbounded store read.
PageLimit1000 = Annotated[int, Query(ge=1, le=1000)]


def reject_unknown_fields(body: object, accepted: Iterable[str]) -> None:
    """Reject a body carrying keys the route does not read.

    A dropped key is indistinguishable from an applied one in the response, so a
    misspelled field silently does nothing. Naming the offender and listing the
    accepted keys turns that into an actionable error.
    """
    if not isinstance(body, dict):
        return
    accepted_keys = frozenset(accepted)
    unknown = sorted(str(key) for key in body if str(key) not in accepted_keys)
    if not unknown:
        return
    raise HTTPException(
        status_code=400,
        detail=(
            f"Unknown field(s) in request body: {unknown}. Accepted: {sorted(accepted_keys)}. "
            "Unknown fields are rejected rather than dropped so a misspelled field is never a silent no-op."
        ),
    )


def _declared_query_names(dependant: object) -> set[str]:
    names = {str(getattr(field, "alias", "")) for field in getattr(dependant, "query_params", [])}
    for child in getattr(dependant, "dependencies", []):
        names |= _declared_query_names(child)
    return names


def reject_unknown_query_params(request: Request) -> None:
    """Route dependency: reject query parameters the route does not declare.

    FastAPI drops undeclared query parameters, so ``?kev_only=true`` returned
    the unfiltered queue as if it were filtered. Undeclared names are a 422,
    the status FastAPI already uses for an invalid query value.
    """
    route = request.scope.get("route")
    dependant = getattr(route, "dependant", None)
    if dependant is None:
        return
    accepted = _declared_query_names(dependant)
    unknown = sorted({key for key in request.query_params if key not in accepted})
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown query parameter(s): {unknown}. Accepted: {sorted(accepted)}.",
        )


def require_scalar_str(body: dict, key: str, *, default: str = "", max_length: int = 200) -> str:
    """Read a string field without coercing a structured value into one.

    ``str(body.get(key))`` turns a dict or list into its Python repr and stores
    it, so a malformed client request became a real record with a nonsense
    identifier. Only JSON scalars are accepted.
    """
    raw = body.get(key, default)
    if raw is None:
        return ""
    if isinstance(raw, bool | int | float):
        raw = str(raw)
    if not isinstance(raw, str):
        raise HTTPException(
            status_code=400,
            detail=f"'{key}' must be a string, got: {type(raw).__name__}",
        )
    return raw.strip()[:max_length]
