"""Decide whether a string-built outbound URL can change scheme or host.

The SSRF rule targets callers steering a request to a host they choose. A URL
is *pinned* when its scheme and host cannot vary:

* the leading literal text already closes the authority
  (``f"https://huggingface.co/api/models/{repo_id}"``);
* it starts with a value that cannot carry caller input (a module constant or
  operator-configuration constant) immediately followed by a literal ``/``,
  ``?`` or ``#`` (``f"{_HF_API}/models/{repo_id}"``);
* the whole value cannot carry caller input; or
* it was passed to a validator (``validate_url(url)``) earlier in the
  function and not rebound since.

A constant base followed directly by an interpolation is not pinned: the
suffix could start ``@attacker.example``.
"""

from __future__ import annotations

import ast
import re

from agent_bom.ast.safe_values import SafeValueScope

_AUTHORITY_CLOSED_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]+[/?#]")
_PATH_START = ("/", "?", "#")
_MAX_NAME_DEPTH = 4


def _parts(expr: ast.AST) -> list[ast.AST] | None:
    if isinstance(expr, ast.JoinedStr):
        return [part.value if isinstance(part, ast.FormattedValue) else part for part in expr.values]
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left, right = _parts(expr.left), _parts(expr.right)
        return [*(left if left is not None else [expr.left]), *(right if right is not None else [expr.right])]
    return None


def _literal(part: ast.AST) -> str | None:
    return part.value if isinstance(part, ast.Constant) and isinstance(part.value, str) else None


def _prefix_pins_host(parts: list[ast.AST], scope: SafeValueScope, line: int) -> bool:
    if not parts:
        return False
    first = parts[0]
    if _literal(first) is None:
        follower = _literal(parts[1]) if len(parts) > 1 else None
        return scope.is_safe(first, line) and follower is not None and follower.startswith(_PATH_START)
    text = ""
    for part in parts:
        literal = _literal(part)
        if literal is None:
            return False
        text += literal
        if _AUTHORITY_CLOSED_RE.match(text):
            return True
    return False


def url_is_pinned(expr: ast.AST | None, scope: SafeValueScope, line: int, depth: int = 0) -> bool:
    """True when ``expr`` cannot select the scheme or host of the request."""
    if expr is None or depth > _MAX_NAME_DEPTH:
        return False
    if scope.validated(expr, line) or scope.is_safe(expr, line):
        return True
    if isinstance(expr, ast.Name):
        return _name_pinned(expr.id, scope, line, depth)
    parts = _parts(expr)
    return parts is not None and _prefix_pins_host(parts, scope, line)


def _name_pinned(name: str, scope: SafeValueScope, line: int, depth: int) -> bool:
    bindings = scope.bindings
    values = bindings.values.get(name, [])
    if name in scope.params or not values or name in bindings.opaque:
        return False
    if bindings.augments.get(name) or bindings.iterations.get(name):
        return False
    return all(url_is_pinned(value, scope, line, depth + 1) for value, _, _ in values)
