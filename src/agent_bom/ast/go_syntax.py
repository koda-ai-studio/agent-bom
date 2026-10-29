"""Bounded Go source argument and delimiter parsing helpers."""

from __future__ import annotations

import re


def _split_top_level_args(args_body: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    paren_depth = brace_depth = bracket_depth = 0
    in_quote = ""
    escaped = False
    for char in args_body:
        if in_quote:
            current.append(char)
            if in_quote != "`" and char == "\\" and not escaped:
                escaped = True
                continue
            if char == in_quote and (in_quote == "`" or not escaped):
                in_quote = ""
            escaped = False
            continue
        if char in {'"', "'", "`"}:
            in_quote = char
            current.append(char)
            escaped = False
            continue
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth -= 1
        elif char == "," and paren_depth == 0 and brace_depth == 0 and bracket_depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _go_param_names(params_segment: str) -> list[str]:
    params: list[str] = []
    pending_names: list[str] = []
    for part in _split_top_level_args(params_segment):
        normalized = part.strip()
        if not normalized:
            continue
        normalized = normalized.lstrip("*")
        if " " not in normalized:
            if re.fullmatch(r"[A-Za-z_]\w*", normalized):
                pending_names.append(normalized)
            continue
        tokens = [token for token in normalized.replace("...", " ").split() if token]
        if len(tokens) < 2:
            continue
        explicit_names = [token.rstrip(",") for token in tokens[:-1] if re.fullmatch(r"[A-Za-z_]\w*", token.rstrip(","))]
        if pending_names or explicit_names:
            params.extend(pending_names + explicit_names)
            pending_names = []
    params.extend(pending_names)
    deduped: list[str] = []
    seen: set[str] = set()
    for name in params:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def _balanced_segment(source: str, open_index: int, *, open_char: str, close_char: str) -> tuple[str, int] | None:
    # Go-specific override of the shared ast_signal_utils._balanced_segment: Go
    # has backtick raw string literals (`...`) in which backslashes are literal,
    # so they need distinct quote handling to avoid miscounting brace/paren depth.
    if open_index < 0 or open_index >= len(source) or source[open_index] != open_char:
        return None
    depth = 0
    in_quote = ""
    escaped = False
    for index in range(open_index, len(source)):
        char = source[index]
        if in_quote:
            if in_quote != "`" and char == "\\" and not escaped:
                escaped = True
                continue
            if char == in_quote and (in_quote == "`" or not escaped):
                in_quote = ""
            escaped = False
            continue
        if char in {'"', "'", "`"}:
            in_quote = char
            escaped = False
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return source[open_index : index + 1], index + 1
    return None
