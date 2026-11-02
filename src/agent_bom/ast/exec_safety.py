"""Sink shapes whose syntax already rules out the attack the rule names.

* YAML loaders declared in the module that subclass ``SafeLoader`` /
  ``CSafeLoader`` (directly or through another such subclass) and never
  register a ``python/`` tag or an unsafe constructor.
* ``subprocess`` calls that execute a fixed, non-shell, non-interpreter
  program from an argv list without ``shell=True``: the call cannot run a
  command the caller chooses. Argument injection into that program is a
  data-flow question the taint rules still answer.
"""

from __future__ import annotations

import ast
import posixpath

_SAFE_LOADER_BASES = frozenset({"yaml.SafeLoader", "SafeLoader", "yaml.CSafeLoader", "CSafeLoader"})
_UNSAFE_CONSTRUCTOR_HINTS = ("python/", "construct_python", "UnsafeConstructor", "FullConstructor", "UnsafeLoader")
_SHELL_OR_INTERPRETER = frozenset(
    {
        "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
        "python", "python3", "python2", "py", "node", "deno", "bun", "perl", "ruby", "php", "lua", "osascript",
        "env", "xargs", "sudo", "su", "doas", "eval", "exec", "busybox", "nohup", "timeout", "nice", "watch",
    }
)  # fmt: skip
_SHELL_FREE_CALLS = frozenset({"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"})


def _dotted(expr: ast.AST) -> str:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        inner = _dotted(expr.value)
        return f"{inner}.{expr.attr}" if inner else ""
    return ""


def safe_yaml_loaders(tree: ast.Module) -> frozenset[str]:
    """Names of module-level loader classes that only construct plain YAML types."""
    classes = {stmt.name: stmt for stmt in tree.body if isinstance(stmt, ast.ClassDef)}
    tainted = {
        _dotted(call.func.value)
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in {"add_constructor", "add_multi_constructor"}
        and any(hint in ast.unparse(arg) for arg in [*call.args, *(k.value for k in call.keywords)] for hint in _UNSAFE_CONSTRUCTOR_HINTS)
    }
    safe: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, cls in classes.items():
            if name in safe or name in tainted or not cls.bases:
                continue
            if all(_dotted(base) in _SAFE_LOADER_BASES or _dotted(base) in safe for base in cls.bases):
                safe.add(name)
                changed = True
    return frozenset(safe)


def _program_is_fixed(argv: ast.AST) -> bool:
    if not isinstance(argv, (ast.List, ast.Tuple)) or not argv.elts:
        return False
    program = argv.elts[0]
    if not (isinstance(program, ast.Constant) and isinstance(program.value, str)):
        return False
    name = posixpath.basename(program.value.strip()).lower()
    base = name.rsplit(".exe", 1)[0] if name.endswith(".exe") else name
    return bool(name) and not name.startswith("-") and base not in _SHELL_OR_INTERPRETER and not base.startswith("python")


def _argv_name_fixed(name: str, func: ast.AST) -> bool:
    assigned = False
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            if len(node.targets) != 1 or not _program_is_fixed(node.value):
                return False
            assigned = True
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name) and node.target.id == name:
            if isinstance(node, ast.AnnAssign) and (node.value is None or not _program_is_fixed(node.value)):
                return False
            if isinstance(node, ast.AugAssign) and not isinstance(node.op, ast.Add):
                return False
            assigned = assigned or isinstance(node, ast.AnnAssign)
        elif name in _loop_or_context_targets(node):
            return False
    return assigned


def _loop_or_context_targets(node: ast.AST) -> set[str]:
    targets: list[ast.AST] = []
    if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension, ast.NamedExpr)):
        targets = [node.target]
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        targets = [item.optional_vars for item in node.items if item.optional_vars is not None]
    return {n.id for target in targets for n in ast.walk(target) if isinstance(n, ast.Name)}


def runs_fixed_program(call_name: str, call: ast.Call, func: ast.AST) -> bool:
    """``subprocess.run(["docker", "ps"])``-shaped: fixed program, argv list, no shell."""
    if call_name not in _SHELL_FREE_CALLS:
        return False
    for keyword in call.keywords:
        if keyword.arg == "shell" and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False):
            return False
        if keyword.arg == "executable":
            return False
    argv = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "args"), None)
    if argv is None:
        return False
    if isinstance(argv, ast.Name):
        return _argv_name_fixed(argv.id, func)
    return _program_is_fixed(argv)
