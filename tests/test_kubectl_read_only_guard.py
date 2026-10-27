"""Collectors only ever run read-only kubectl verbs against a cluster.

Scans every function that builds a ``kubectl`` command (a list literal holding
``"kubectl"``) and every call to a ``*kubectl*`` helper with a literal verb.
A mutating or exec-style verb in any argv list of those is a read-only violation.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom"

# Operator-run teardown of agent-bom's own deployment, never a scan collector.
_ALLOWED_FILES = {"deploy_teardown.py"}

_FORBIDDEN_VERBS = frozenset(
    {
        "annotate",
        "apply",
        "attach",
        "autoscale",
        "cordon",
        "cp",
        "create",
        "debug",
        "delete",
        "drain",
        "edit",
        "exec",
        "expose",
        "label",
        "patch",
        "port-forward",
        "replace",
        "rollout",
        "run",
        "scale",
        "set",
        "taint",
        "uncordon",
    }
)


def _string_constants(node: ast.AST) -> list[str]:
    """String elements of every list/tuple literal (command argv) under ``node``."""
    return [
        elt.value
        for seq in ast.walk(node)
        if isinstance(seq, (ast.List, ast.Tuple))
        for elt in seq.elts
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
    ]


def _builds_kubectl_command(func: ast.AST) -> bool:
    for node in ast.walk(func):
        if isinstance(node, (ast.List, ast.Tuple)) and any(isinstance(elt, ast.Constant) and elt.value == "kubectl" for elt in node.elts):
            return True
    return False


def _callee_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _literal_verb(call: ast.Call) -> str | None:
    if not call.args:
        return None
    first = call.args[0]
    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
        first = first.elts[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    rel = path.relative_to(SRC)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _builds_kubectl_command(node):
            for value in _string_constants(node):
                if value in _FORBIDDEN_VERBS:
                    found.append(f"{rel}:{node.lineno} {node.name}() builds kubectl {value!r}")
        if isinstance(node, ast.Call) and "kubectl" in _callee_name(node).lower():
            verb = _literal_verb(node)
            if verb in _FORBIDDEN_VERBS:
                found.append(f"{rel}:{node.lineno} {_callee_name(node)}({verb!r})")
    return found


def test_no_collector_runs_a_mutating_or_exec_kubectl_verb() -> None:
    violations = [violation for path in sorted(SRC.rglob("*.py")) if path.name not in _ALLOWED_FILES for violation in _violations(path)]
    assert violations == [], "kubectl must stay read-only:\n" + "\n".join(violations)


def test_guard_detects_exec_through_extend(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        'def probe(ctx):\n    cmd = ["kubectl"]\n    cmd.extend(["exec", "-n", "default", "--", "sh"])\n    return cmd\n',
        encoding="utf-8",
    )
    tree = ast.parse(sample.read_text(encoding="utf-8"))
    func = tree.body[0]
    assert _builds_kubectl_command(func)
    assert "exec" in _string_constants(func)


def test_guard_detects_mutating_helper_call() -> None:
    call = ast.parse('_run_kubectl(["delete", "pod", "x"])').body[0].value
    assert isinstance(call, ast.Call)
    assert _literal_verb(call) == "delete"
