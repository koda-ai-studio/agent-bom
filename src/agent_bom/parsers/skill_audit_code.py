"""Fenced code-block helpers for skill audits: Python call names and JS/TS call extraction."""

from __future__ import annotations

import ast
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


_PYTHON_FENCED_BLOCK_RE = re.compile(r"```(?:python|py)\s*\n([\s\S]*?)```", re.IGNORECASE)
_JS_TS_FENCED_BLOCK_RE = re.compile(
    r"```(?P<language>javascript|js|typescript|ts|tsx|jsx)\s*\n(?P<code>[\s\S]*?)```",
    re.IGNORECASE,
)

_DYNAMIC_CODE_CALLS = {"eval", "exec", "compile", "__import__"}
_SUBPROCESS_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}
_FILE_MUTATION_CALLS = {
    "open",
    "Path.write_text",
    "Path.write_bytes",
    "Path.touch",
    "Path.unlink",
    "Path.rename",
    "Path.replace",
}
_JS_DYNAMIC_CODE_CALLS = {"eval", "Function"}
_JS_SUBPROCESS_CALLS = {
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "fork",
    "child_process.exec",
    "child_process.execSync",
    "child_process.spawn",
    "child_process.spawnSync",
    "child_process.fork",
}
_JS_FILE_MUTATION_CALLS = {
    "fs.writeFile",
    "fs.writeFileSync",
    "fs.appendFile",
    "fs.appendFileSync",
    "fs.unlink",
    "fs.unlinkSync",
    "fs.rm",
    "fs.rmSync",
    "fs.rename",
    "fs.renameSync",
    "fs.promises.writeFile",
    "fs.promises.appendFile",
    "fs.promises.unlink",
    "fs.promises.rm",
    "fs.promises.rename",
    "Bun.write",
    "Deno.writeTextFile",
    "Deno.writeFile",
    "Deno.remove",
    "Deno.rename",
}
_JS_CALL_RE = re.compile(r"\b(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*\s*\(")
_JS_IMPORT_NAMED_RE = re.compile(
    r"""import\s*\{\s*([^}]+)\}\s*from\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_JS_IMPORT_NAMESPACE_RE = re.compile(
    r"""import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_JS_IMPORT_DEFAULT_RE = re.compile(
    r"""import\s+([A-Za-z_$][\w$]*)\s+from\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_JS_REQUIRE_NAMED_RE = re.compile(
    r"""(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*require\(\s*["']([^"']+)["']\s*\)""",
    re.IGNORECASE,
)
_JS_REQUIRE_DEFAULT_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["']([^"']+)["']\s*\)""",
    re.IGNORECASE,
)
_JS_IMPORTABLE_SUBPROCESS_CALLS = {
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "fork",
}
_JS_IMPORTABLE_FILE_MUTATION_CALLS = {
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "unlink",
    "unlinkSync",
    "rm",
    "rmSync",
    "rename",
    "renameSync",
    "writeTextFile",
    "writeFile",
    "remove",
    "rename",
}


def _line_column(content: str, offset: int) -> tuple[int, int]:
    """Return 1-based line and column for an offset."""
    line = content.count("\n", 0, offset) + 1
    last_newline = content.rfind("\n", 0, offset)
    column = offset + 1 if last_newline == -1 else offset - last_newline
    return line, column


def _call_name(node: ast.AST) -> str:
    """Return a dotted call name when possible."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _open_mode_is_mutating(call: ast.Call) -> bool:
    """Return True when open(...) uses a mutating mode."""
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        return any(flag in call.args[1].value for flag in ("w", "a", "+"))
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return any(flag in keyword.value.value for flag in ("w", "a", "+"))
    return False


def _strip_js_strings_and_comments(code: str) -> str:
    """Remove JS/TS strings and comments while preserving call structure."""
    result: list[str] = []
    i = 0
    length = len(code)
    state = "code"
    quote = ""

    while i < length:
        char = code[i]
        nxt = code[i + 1] if i + 1 < length else ""

        if state == "code":
            if char == "/" and nxt == "/":
                state = "line_comment"
                result.extend("  ")
                i += 2
                continue
            if char == "/" and nxt == "*":
                state = "block_comment"
                result.extend("  ")
                i += 2
                continue
            if char in {"'", '"', "`"}:
                state = "string"
                quote = char
                result.append(" ")
                i += 1
                continue
            result.append(char)
            i += 1
            continue

        if state == "line_comment":
            if char == "\n":
                state = "code"
                result.append("\n")
            else:
                result.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                state = "code"
                result.extend("  ")
                i += 2
            else:
                result.append("\n" if char == "\n" else " ")
                i += 1
            continue

        if state == "string":
            if char == "\\" and i + 1 < length:
                result.extend("  ")
                i += 2
                continue
            if char == quote:
                state = "code"
                quote = ""
                result.append(" ")
            else:
                result.append("\n" if char == "\n" else " ")
            i += 1
            continue

    return "".join(result)


def _normalize_js_module_name(module_name: str) -> str:
    module_name = module_name.strip()
    if module_name.startswith("node:"):
        module_name = module_name[5:]
    return module_name


def _canonical_js_function_call(module_name: str, imported_name: str) -> str | None:
    module_name = _normalize_js_module_name(module_name)
    imported_name = imported_name.strip()
    if module_name == "child_process" and imported_name in _JS_IMPORTABLE_SUBPROCESS_CALLS:
        return f"child_process.{imported_name}"
    if module_name == "fs" and imported_name in _JS_IMPORTABLE_FILE_MUTATION_CALLS:
        return f"fs.{imported_name}"
    if module_name == "fs/promises" and imported_name in _JS_IMPORTABLE_FILE_MUTATION_CALLS:
        return f"fs.promises.{imported_name}"
    if module_name == "fs/promises" and imported_name == "default":
        return "fs.promises"
    return None


def _canonical_js_namespace(module_name: str) -> str | None:
    module_name = _normalize_js_module_name(module_name)
    if module_name == "child_process":
        return "child_process"
    if module_name == "fs":
        return "fs"
    if module_name == "fs/promises":
        return "fs.promises"
    return None


def _split_js_import_spec(spec: str) -> tuple[str, str]:
    if " as " in spec:
        imported, alias = spec.split(" as ", 1)
        return imported.strip(), alias.strip()
    if ":" in spec:
        imported, alias = spec.split(":", 1)
        return imported.strip(), alias.strip()
    spec = spec.strip()
    return spec, spec


def _collect_js_aliases(code: str) -> tuple[dict[str, str], dict[str, str]]:
    function_aliases: dict[str, str] = {}
    namespace_aliases: dict[str, str] = {}

    for match in _JS_IMPORT_NAMED_RE.finditer(code):
        specs, module_name = match.groups()
        for raw_spec in specs.split(","):
            imported, alias = _split_js_import_spec(raw_spec)
            canonical = _canonical_js_function_call(module_name, imported)
            if canonical:
                function_aliases[alias] = canonical

    for match in _JS_REQUIRE_NAMED_RE.finditer(code):
        specs, module_name = match.groups()
        for raw_spec in specs.split(","):
            imported, alias = _split_js_import_spec(raw_spec)
            canonical = _canonical_js_function_call(module_name, imported)
            if canonical:
                function_aliases[alias] = canonical

    for match in _JS_IMPORT_NAMESPACE_RE.finditer(code):
        alias, module_name = match.groups()
        canonical = _canonical_js_namespace(module_name)
        if canonical:
            namespace_aliases[alias] = canonical

    for match in _JS_IMPORT_DEFAULT_RE.finditer(code):
        alias, module_name = match.groups()
        canonical = _canonical_js_namespace(module_name)
        if canonical:
            namespace_aliases[alias] = canonical

    for match in _JS_REQUIRE_DEFAULT_RE.finditer(code):
        alias, module_name = match.groups()
        canonical = _canonical_js_namespace(module_name)
        if canonical:
            namespace_aliases[alias] = canonical

    return function_aliases, namespace_aliases


def _canonicalize_js_call_name(call_name: str, function_aliases: dict[str, str], namespace_aliases: dict[str, str]) -> str:
    call_name = call_name.strip()
    if call_name in function_aliases:
        return function_aliases[call_name]

    if "." not in call_name:
        return call_name

    base, remainder = call_name.split(".", 1)
    if base in namespace_aliases:
        return f"{namespace_aliases[base]}.{remainder}"
    return call_name


def _collect_js_ts_call_names(block: str, *, language_hint: str) -> set[str]:
    """Collect JS/TS call names via tree-sitter when available, otherwise regex fallback."""
    analyze_js_ts_block: Any | None = None
    ast_unavailable_error: type[Exception] = RuntimeError
    try:
        from agent_bom.ast.js_ts import JSTSAstUnavailableError
        from agent_bom.ast.js_ts import analyze_js_ts_block as analyze_js_ts_block_impl

        analyze_js_ts_block = analyze_js_ts_block_impl
        ast_unavailable_error = JSTSAstUnavailableError
    except Exception:  # pragma: no cover - defensive import guard
        pass

    if analyze_js_ts_block is not None:
        try:
            return analyze_js_ts_block(block, language_hint=language_hint).call_names
        except ast_unavailable_error:
            logger.debug("tree-sitter JS/TS runtime unavailable; falling back to regex analysis")
        except Exception:
            logger.debug("tree-sitter JS/TS analysis failed; falling back to regex analysis", exc_info=True)

    function_aliases, namespace_aliases = _collect_js_aliases(block)
    normalized = _strip_js_strings_and_comments(block)
    call_names = {
        _canonicalize_js_call_name(match.group(0).rstrip("(").strip(), function_aliases, namespace_aliases)
        for match in _JS_CALL_RE.finditer(normalized)
    }
    if re.search(r"\bnew\s+Function\s*\(", normalized):
        call_names.add("Function")
    return call_names
