"""Collapse per-occurrence CI-hardening warnings into one console line per rule."""

from __future__ import annotations

import re

_HARDENING_RE = re.compile(r"^CI hardening in (?P<file>\S+): (?P<reason>[^;]+); (?P<advice>.+)$")
_UNPINNED_PREFIX = "unpinned action "


def _rule_and_subject(reason: str) -> tuple[str, str | None]:
    if reason.startswith(_UNPINNED_PREFIX):
        return _UNPINNED_PREFIX.rstrip(), reason[len(_UNPINNED_PREFIX) :].strip() or None
    return reason, None


def _format_group(rule: str, advice: str, occurrences: list[tuple[str, str | None]]) -> str:
    per_file: dict[str, list[str]] = {}
    for filename, subject in occurrences:
        per_file.setdefault(filename, [])
        if subject:
            per_file[filename].append(subject)
    if any(per_file.values()):
        where = "; ".join(f"{name}: {', '.join(subjects)}" if subjects else name for name, subjects in per_file.items())
    else:
        where = ", ".join(per_file)
    return f"CI hardening: {rule} × {len(occurrences)} ({where}); {advice}"


def dedupe_hardening_warnings(warnings: list[str]) -> list[str]:
    """Return ``warnings`` with repeated CI-hardening rules merged into one counted line.

    A rule that fires once keeps its original text. Warnings that are not
    CI-hardening lines pass through unchanged, in their original order.
    """
    groups: dict[tuple[str, str], list[tuple[str, str | None]]] = {}
    originals: dict[tuple[str, str], str] = {}
    ordered: list[tuple[str, tuple[str, str] | None]] = []
    for warning in warnings:
        match = _HARDENING_RE.match(warning)
        if match is None:
            ordered.append((warning, None))
            continue
        rule, subject = _rule_and_subject(match.group("reason").strip())
        group_key = (rule, match.group("advice").strip())
        if group_key not in groups:
            groups[group_key] = []
            originals[group_key] = warning
            ordered.append((warning, group_key))
        groups[group_key].append((match.group("file"), subject))

    lines: list[str] = []
    for warning, key in ordered:
        if key is None or len(groups[key]) == 1:
            lines.append(warning if key is None else originals[key])
        else:
            lines.append(_format_group(key[0], key[1], groups[key]))
    return lines


__all__ = ["dedupe_hardening_warnings"]
