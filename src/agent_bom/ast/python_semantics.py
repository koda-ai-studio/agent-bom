"""Python syntax predicates and detection patterns."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_bom.ast.python_structure import _call_name as _call_name
from agent_bom.ast.python_structure import _expr_name as _expr_name
from agent_bom.ast.sql_safety import expr_uses_dynamic_string as _expr_uses_dynamic_string
from agent_bom.ast_models import ApplicationEntrypoint, _FunctionAnalysis
from agent_bom.traversal import VENDOR_SKIP_DIRS

_GUARDRAIL_IMPORTS = {
    "guardrails": ("Guardrails AI", "content_filter"),
    "nemoguardrails": ("NeMo Guardrails", "content_filter"),
    "llm_guard": ("LLM Guard", "input_validator"),
    "rebuff": ("Rebuff", "input_validator"),
    "lakera": ("Lakera Guard", "input_validator"),
    "presidio_analyzer": ("Presidio", "pii_filter"),
    "presidio_anonymizer": ("Presidio Anonymizer", "pii_filter"),
    "langchain.callbacks": ("LangChain Callbacks", "output_validator"),
    "anthropic.types": ("Anthropic Safety", "content_filter"),
}


_FRAMEWORK_IMPORTS: dict[str, str] = {
    "langchain": "LangChain",
    "langchain_core": "LangChain",
    "langchain_community": "LangChain",
    "langgraph": "LangGraph",
    "crewai": "CrewAI",
    "autogen": "AutoGen",
    "mcp": "MCP",
    "modelcontextprotocol": "MCP",
    "llama_index": "LlamaIndex",
    "semantic_kernel": "Semantic Kernel",
}


def _import_matches_module(module: str, target: str) -> bool:
    """True when *module* is *target* or a submodule of it.

    Whole dotted modules only. A substring test used to accept
    ``nemoguardrails`` for the ``guardrails`` entry — NVIDIA's documented
    ``from nemoguardrails import LLMRails`` then produced two guardrails, the
    extra one credited to the wrong vendor — and accepted any project-local
    module whose name merely contained a vendor's, such as
    ``app.guardrails_config``.
    """
    return module == target or module.startswith(f"{target}.")


_DYNAMIC_CODE_CALLS = {"eval", "exec", "compile", "__import__"}


_SENSITIVE_CREDENTIAL_PATH_FRAGMENTS = (
    "/.aws/credentials",
    "/.aws/config",
    "/.config/gcloud/application_default_credentials.json",
    "/.docker/config.json",
    "/.kube/config",
    "/.ssh/id_",
)


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


_PATH_ACCESS_CALLS = {
    "open",
    "Path.open",
    "Path.read_text",
    "Path.read_bytes",
    "Path.write_text",
    "Path.write_bytes",
    "send_file",
    "send_from_directory",
}


_HTTP_CLIENT_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.request",
    "urllib.request.urlopen",
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
    "aiohttp.ClientSession.request",
}


_SQL_CALLS = {"execute", "executemany", "cursor.execute", "cursor.executemany"}


_UNSAFE_DESERIALIZATION_CALLS = {
    "pickle.load",
    "pickle.loads",
    "yaml.load",
    "yaml.unsafe_load",
    "marshal.loads",
    "dill.loads",
    "jsonpickle.decode",
}


_XSS_CALLS = {"render_template_string", "Markup", "markupsafe.Markup"}


_LLM_CALL_SUBSTRINGS = (
    "chat.completions.create",
    "responses.create",
    "messages.create",
    "completions.create",
    "generate_content",
    "generatecontent",
    "ollama.chat",
    "ollama.generate",
)


_UNTRUSTED_SOURCE_CALLS = {
    "input",
    "request.get_json",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.headers.get",
    "sys.argv",
}


_REQUEST_GLOBAL_MODULES = frozenset({"flask", "quart"})


_REQUEST_DATA_ATTRIBUTES = frozenset({"args", "form", "json", "values", "headers", "cookies", "data", "files", "view_args"})


_INJECTED_DEPENDENCY_CALLS = frozenset({"Depends", "Security"})


_SANITIZER_CALLS = {
    "html.escape",
    "markupsafe.escape",
    "shlex.quote",
    "urllib.parse.quote",
    "secure_filename",
    "werkzeug.utils.secure_filename",
    "safe_join",
    "werkzeug.utils.safe_join",
    "os.path.basename",
}


_SKIP_DIRS = VENDOR_SKIP_DIRS | frozenset(
    {
        "env",
        ".env",
        "tests",
        "test",
        "testing",
        "fixtures",
        "fuzz",
        "vendor",
    }
)


_SKIP_FILE_PATTERNS = frozenset(
    {
        "patterns.py",
        "conftest.py",
        "test_",
        "_test.py",
        "fixture",
        "mock",
        "fake",
        "sample",
    }
)


_MAX_FILE_SIZE = 512 * 1024  # 512KB


_MAX_FILES = 5_000  # Prioritize entrypoints; report a coverage warning when this budget is exhausted.


_VALIDATION_HINTS = (
    "allow",
    "approve",
    "auth",
    "check",
    "confirm",
    "guard",
    "permit",
    "safe",
    "sanitize",
    "validate",
    "verify",
)


_DANGEROUS_CALLS = _DYNAMIC_CODE_CALLS | _SUBPROCESS_CALLS | _FILE_MUTATION_CALLS


_JS_TS_UNTRUSTED_DATA_RE = re.compile(
    r"\b(?:user[A-Z_]\w*|user\w*|input|payload|req(?:uest)?\.(?:body|query|params)|ctx\.(?:body|query|params)|process\.env)\b",
    re.IGNORECASE,
)


def _keyword_value(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


_FRAMEWORK_TOOL_ROOTS: dict[str, str] = {
    "langchain": "LangChain",
    "langchain_core": "LangChain",
    "langchain_community": "LangChain",
    "langgraph": "LangGraph",
    "crewai": "CrewAI",
    "llama_index": "LlamaIndex",
    "autogen": "AutoGen",
    "autogen_agentchat": "AutoGen",
    "pydantic_ai": "Pydantic AI",
    "semantic_kernel": "Semantic Kernel",
}


_FRAMEWORK_AGENT_CONSTRUCTORS = frozenset(
    {
        "Agent",
        "AgentExecutor",
        "Crew",
        "create_react_agent",
        "create_openai_functions_agent",
        "initialize_agent",
    }
)


_FRAMEWORK_TOOL_CONSTRUCTORS = frozenset({"Tool", "StructuredTool", "FunctionTool", "DynamicTool", "ToolWrapper", "tool"})


_FRAMEWORK_TOOL_HANDLER_KEYWORDS = ("func", "coroutine", "function", "callback", "handler")


def _call_references_sensitive_credential_path(call: ast.Call) -> bool:
    """Return whether a call contains a known credential-file path literal.

    Only literals are inspected and no path value is copied into a finding, so
    dynamic paths are not guessed and credential-bearing locations stay out of
    machine output.
    """
    for node in ast.walk(call):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        normalized = node.value.strip().lower().replace("\\", "/")
        if any(fragment in normalized for fragment in _SENSITIVE_CREDENTIAL_PATH_FRAGMENTS):
            return True
    return False


def _is_privilege_escalation_call_name(call_name: str) -> bool:
    normalized = call_name.strip().lower()
    return normalized == "assume_role" or normalized.endswith(".assume_role")


def _module_name_for_rel_path(rel_path: str) -> str:
    path = Path(rel_path)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _open_mode_is_mutating(call: ast.Call) -> bool:
    """Return True when open(...) uses a mutating mode."""
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        return any(flag in call.args[1].value for flag in ("w", "a", "+"))
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return any(flag in keyword.value.value for flag in ("w", "a", "+"))
    return False


def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Return a child→parent map for AST nodes."""
    parent_map: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent
    return parent_map


def _expr_contains_validation_hint(node: ast.AST) -> bool:
    """Return True when an expression contains validation/authorization hints."""

    def is_literal_allowlist(expr: ast.AST) -> bool:
        if isinstance(expr, (ast.Set, ast.List, ast.Tuple)):
            return bool(expr.elts) and all(isinstance(elt, ast.Constant) for elt in expr.elts)
        return False

    for child in ast.walk(node):
        if isinstance(child, ast.Name) and any(hint in child.id.lower() for hint in _VALIDATION_HINTS):
            return True
        if isinstance(child, ast.Attribute) and any(hint in child.attr.lower() for hint in _VALIDATION_HINTS):
            return True
        if isinstance(child, ast.Compare):
            if any(isinstance(op, ast.In) for op in child.ops) and any(
                is_literal_allowlist(expr) for expr in [child.left, *child.comparators]
            ):
                return True
        if isinstance(child, ast.Call):
            call_name = _call_name(child.func).lower()
            if any(hint in call_name for hint in _VALIDATION_HINTS):
                return True
            if call_name in {"re.fullmatch", "re.match"} or call_name.endswith((".fullmatch", ".match")):
                return True
    return False


def _validation_source_names_from_expr(expr: ast.AST | None) -> set[str]:
    """Return identifiers directly constrained by a validation expression."""
    if expr is None:
        return set()
    if isinstance(expr, ast.Call):
        names: set[str] = set()
        if isinstance(expr.func, ast.Attribute):
            names.update(_names_in_expr(expr.func.value))
        for arg in expr.args:
            names.update(_names_in_expr(arg))
        for keyword in expr.keywords:
            names.update(_names_in_expr(keyword.value))
        return names
    return _names_in_expr(expr)


def _returns_boolean_constant(statements: list[ast.stmt], value: bool) -> bool:
    return any(
        isinstance(statement, ast.Return) and isinstance(statement.value, ast.Constant) and statement.value.value is value
        for statement in statements
    )


def _branch_definitely_exits(statements: list[ast.stmt]) -> bool:
    """Return True when a branch definitely stops control flow."""
    if not statements:
        return False
    last_statement = statements[-1]
    if isinstance(last_statement, (ast.Return, ast.Raise)):
        return True
    if isinstance(last_statement, ast.If):
        return _branch_definitely_exits(last_statement.body) and _branch_definitely_exits(last_statement.orelse)
    return False


def _is_guarded_call(node: ast.AST, parent_map: dict[ast.AST, ast.AST]) -> bool:
    """Return True when a dangerous call sits behind a validation-oriented branch."""
    current = parent_map.get(node)
    while current is not None and not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        if isinstance(current, ast.If) and _expr_contains_validation_hint(current.test):
            return True
        if isinstance(current, ast.Assert) and _expr_contains_validation_hint(current.test):
            return True
        current = parent_map.get(current)
    return False


def _target_names(node: ast.AST) -> set[str]:
    """Extract assigned identifier names from a target expression."""
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for child in node.elts:
            names.update(_target_names(child))
        return names
    return set()


def _names_in_expr(node: ast.AST | None) -> set[str]:
    """Collect identifier names used by an expression."""
    if node is None:
        return set()
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _is_llm_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    if any(fragment in lower_name for fragment in _LLM_CALL_SUBSTRINGS):
        return True
    if lower_name.endswith((".invoke", ".ainvoke", ".predict", ".apredict")) and any(
        hint in lower_name for hint in ("llm", "model", "chain", "agent")
    ):
        return True
    return False


def _is_sql_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in _SQL_CALLS or lower_name.endswith(".execute") or lower_name.endswith(".executemany")


def _is_http_client_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in _HTTP_CLIENT_CALLS


def _is_path_access_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    if lower_name in {name.lower() for name in _PATH_ACCESS_CALLS}:
        return True
    return lower_name.endswith((".read_text", ".read_bytes", ".write_text", ".write_bytes", ".open"))


def _is_unsafe_deserialization_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in {name.lower() for name in _UNSAFE_DESERIALIZATION_CALLS}


def _uses_safe_yaml_loader(call: ast.Call) -> bool:
    call_name = _call_name(call.func).lower()
    if call_name != "yaml.load":
        return False
    safe_loader_names = {
        "yaml.safeloader",
        "safeloader",
        "yaml.csafeloader",
        "csafeloader",
    }
    for keyword in call.keywords:
        if keyword.arg != "Loader":
            continue
        if _expr_name(keyword.value).lower() in safe_loader_names:
            return True
    if len(call.args) >= 2 and _expr_name(call.args[1]).lower() in safe_loader_names:
        return True
    return False


def _call_keyword_bool(call: ast.Call, name: str) -> bool:
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, bool):
            return keyword.value.value
    return False


def _call_argument_expr(call: ast.Call, *, primary_arg_names: set[str] | None = None) -> ast.AST | None:
    if call.args:
        return call.args[0]
    if primary_arg_names:
        for keyword in call.keywords:
            if keyword.arg in primary_arg_names:
                return keyword.value
    return None


def _is_command_execution_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in {name.lower() for name in _SUBPROCESS_CALLS}


def _is_shell_execution_call(call_name: str, call: ast.Call) -> bool:
    lower_name = call_name.lower()
    if lower_name in {"os.system", "os.popen"}:
        return True
    return _call_keyword_bool(call, "shell")


def _expr_is_dynamic_or_tracked(expr: ast.AST | None, tracked_names: set[str]) -> bool:
    if _expr_uses_dynamic_string(expr):
        return True
    return isinstance(expr, ast.Name) and expr.id in tracked_names


def _is_xss_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in {name.lower() for name in _XSS_CALLS}


def _is_untrusted_source_call(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in _UNTRUSTED_SOURCE_CALLS or lower_name.endswith(".get_json")


def _request_global_is_framework_source(func: _FunctionAnalysis) -> bool:
    module, name = func.imported_functions.get("request", ("", ""))
    if name != "request" or module.split(".", 1)[0] not in _REQUEST_GLOBAL_MODULES or func.node is None:
        return False
    for node in ast.walk(func.node):
        if isinstance(node, ast.Assign):
            if any("request" in _target_names(target) for target in node.targets):
                return False
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor, ast.NamedExpr)):
            if "request" in _target_names(node.target):
                return False
    return "request" not in func.param_names


def _is_request_data_attribute(expr: ast.Attribute) -> bool:
    return isinstance(expr.value, ast.Name) and expr.value.id == "request" and expr.attr in _REQUEST_DATA_ATTRIBUTES


def _route_tainted_params(func: _FunctionAnalysis) -> set[str]:
    """Route handler parameters bound from the request, excluding injected dependencies."""
    if func.node is None:
        return set()
    args = func.node.args
    positional = [*args.posonlyargs, *args.args]
    defaulted = positional[len(positional) - len(args.defaults) :]
    defaults: dict[str, ast.expr] = dict(zip([arg.arg for arg in defaulted], args.defaults, strict=True))
    for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        if default is not None:
            defaults[arg.arg] = default
    tainted: set[str] = set()
    for arg in [*positional, *args.kwonlyargs]:
        if arg.arg in {"self", "cls"}:
            continue
        default = defaults.get(arg.arg)
        if isinstance(default, ast.Call) and _call_name(default.func).rsplit(".", 1)[-1] in _INJECTED_DEPENDENCY_CALLS:
            continue
        tainted.add(arg.arg)
    return tainted


def _application_entrypoint_matches(
    functions: list[_FunctionAnalysis],
    application_entrypoints: list[ApplicationEntrypoint] | None,
    *,
    kinds: frozenset[str] | None = None,
) -> list[tuple[int, ApplicationEntrypoint, _FunctionAnalysis]]:
    matches: list[tuple[int, ApplicationEntrypoint, _FunctionAnalysis]] = []
    for index, entry in enumerate(application_entrypoints or []):
        if kinds is not None and entry.kind not in kinds:
            continue
        handler = entry.handler.rsplit(".", 1)[-1]
        candidates = [func for func in functions if func.simple_name == handler and func.file_path == entry.file_path]
        if len(candidates) == 1:
            matches.append((index, entry, candidates[0]))
    return matches


def _is_sanitizer_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    # Security-sensitive APIs whose names happen to contain a validation hint
    # (notably ``subprocess.check_output``) are sinks, never sanitizers.
    if lower_name in {name.lower() for name in _DANGEROUS_CALLS}:
        return False
    if lower_name in _SANITIZER_CALLS:
        return True
    return any(hint in lower_name for hint in _VALIDATION_HINTS)
