"""Read-only local impact reporting with bounded input and exclusive output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from agent_bom.output.impact_brief import MAX_BYTES, build_impact_brief
from agent_bom.output.impact_html import render_impact_brief


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input exceeds report budget")
    value = json.loads(raw, object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise ValueError("scan report must be an object")
    return value


def write_impact_brief(scan_json: Path, *, before: Path | None, limit: int, output_format: str, output: Path) -> None:
    try:
        if output.exists():
            raise ValueError("output exists")
        brief = build_impact_brief(_read(scan_json), before=_read(before) if before else None, limit=limit)
        text = render_impact_brief(brief) if output_format == "html" else json.dumps(brief, indent=2, allow_nan=False) + "\n"
        with output.open("x", encoding="utf-8") as stream:
            stream.write(text)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise click.ClickException(
            "Impact brief failed: check scan schema, identities, ordered comparison scope and file permissions; choose a new output path."
        ) from exc
    click.echo(json.dumps({"artifact": str(output), "scan_id": brief["current"]["scan_id"], "verified_fixes": None}))
