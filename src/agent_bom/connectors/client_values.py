"""Path and optional-value encoding shared by control-plane clients."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from agent_bom.core.json_types import JsonObject, QueryValue


def _quote_path(value: str) -> str:
    return quote(value, safe="")


def _strip_none(values: Mapping[str, Any]) -> JsonObject:
    return {key: value for key, value in values.items() if value is not None}


def _strip_query_none(values: Mapping[str, QueryValue]) -> dict[str, str | int | float | bool]:
    return {key: value for key, value in values.items() if value is not None}
