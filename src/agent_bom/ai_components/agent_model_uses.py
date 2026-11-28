"""Read the model(s) a framework agent is configured with, from source only.

Covers constructor arguments (``model=``, ``llm=``, ``model_client=``,
``llm_config=``), chat-model wrappers (``ChatOpenAI(model=...)``,
``LLM("openai/gpt-4o")``, ``init_chat_model("openai:gpt-4o")``), module-level
bindings of those, AutoGen ``llm_config`` / ``config_list`` dicts, CrewAI
``agents.yaml`` entries, and environment-variable lookups. Scanned code is
parsed, never imported or run, and an environment variable contributes its
name only: its value is never read.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agent_bom.ai_components.framework_models import AgentModelUse
from agent_bom.ai_components.patterns import MODEL_PATTERNS

_AGENT_MODEL_KEYWORDS = ("model", "model_name", "model_id", "llm", "model_client", "llm_config")
_POSITIONAL_MODEL_AGENTS = frozenset({"create_react_agent", "create_agent"})
_WRAPPER_MODEL_KEYWORDS = ("model", "model_name", "model_id", "deployment_name", "azure_deployment")
_POSITIONAL_MODEL_WRAPPERS = frozenset({"init_chat_model", "LLM", "LitellmModel", "ChatLiteLLM"})
_ENV_GETTERS = frozenset({"os.getenv", "getenv", "os.environ.get", "environ.get"})
_CONFIG_MODEL_KEYS = ("model", "config_list")
_MAX_DEPTH = 4
_MAX_CONFIG_BYTES = 256 * 1024
_DEFAULT_CREW_AGENTS_CONFIG = "config/agents.yaml"

_WRAPPER_PROVIDERS = {
    "ChatOpenAI": "openai",
    "OpenAIChatCompletionClient": "openai",
    "OpenAIChatCompletionsModel": "openai",
    "OpenAIResponsesModel": "openai",
    "AzureChatOpenAI": "azure-openai",
    "AzureOpenAIChatCompletionClient": "azure-openai",
    "ChatAnthropic": "anthropic",
    "AnthropicChatCompletionClient": "anthropic",
    "AnthropicBedrockChatCompletionClient": "aws-bedrock",
    "ChatGoogleGenerativeAI": "google",
    "ChatVertexAI": "google",
    "ChatBedrock": "aws-bedrock",
    "ChatBedrockConverse": "aws-bedrock",
    "ChatOllama": "ollama",
    "OllamaChatCompletionClient": "ollama",
    "ChatMistralAI": "mistral",
    "ChatGroq": "groq",
    "ChatCohere": "cohere",
}
_PREFIX_PROVIDERS = {
    "openai": "openai",
    "azure": "azure-openai",
    "azure_openai": "azure-openai",
    "anthropic": "anthropic",
    "google_genai": "google",
    "google_vertexai": "google",
    "gemini": "google",
    "vertex_ai": "google",
    "bedrock": "aws-bedrock",
    "bedrock_converse": "aws-bedrock",
    "ollama": "ollama",
    "groq": "groq",
    "mistral": "mistral",
    "mistralai": "mistral",
    "cohere": "cohere",
    "huggingface": "huggingface",
    "deepseek": "deepseek",
    "xai": "xai",
}


@dataclass
class ModelScope:
    """Per-file lookups a model reference resolves through."""

    tree: ast.Module
    rel_path: str
    file_path: Path
    project_root: Path
    bindings: dict[str, ast.expr] = field(default_factory=dict)
    crew_config: dict[str, tuple[str, int]] | None = None
    crew_config_path: str = ""

    @classmethod
    def build(cls, tree: ast.Module, rel_path: str, file_path: Path, project_root: Path) -> ModelScope:
        return cls(tree, rel_path, file_path, project_root, _module_bindings(tree))


def extract_model_uses(call: ast.Call, short_name: str, scope: ModelScope) -> list[AgentModelUse]:
    """Every model an agent constructor call is configured with, deduplicated in source order."""
    uses: list[AgentModelUse] = []
    for keyword in _AGENT_MODEL_KEYWORDS:
        value = _keyword(call, keyword)
        if value is not None:
            in_config = keyword == "llm_config"
            uses.extend(_resolve(value, scope, via=f"{short_name}({keyword}=)", provider_hint="", in_config=in_config, depth=0))
    if short_name in _POSITIONAL_MODEL_AGENTS and call.args:
        uses.extend(_resolve(call.args[0], scope, via=f"{short_name}(model)", provider_hint="", in_config=False, depth=0))
    uses.extend(_crew_config_uses(call, scope))
    return list(dict.fromkeys(uses))


def infer_provider(model: str, provider_hint: str = "") -> str:
    """Provider from an explicit ``provider:`` / ``provider/`` prefix, the wrapper class, then the model ID's family."""
    for separator in (":", "/"):
        prefix, sep, _ = model.partition(separator)
        if sep and prefix.lower() in _PREFIX_PROVIDERS:
            return _PREFIX_PROVIDERS[prefix.lower()]
    if provider_hint:
        return provider_hint
    quoted = f'"{model.rsplit("/", 1)[-1].rsplit(":", 1)[-1]}"'
    for pattern in MODEL_PATTERNS:
        if pattern.regex.search(quoted):
            return pattern.provider
    return ""


def _resolve(node: ast.AST, scope: ModelScope, *, via: str, provider_hint: str, in_config: bool, depth: int) -> list[AgentModelUse]:
    if depth > _MAX_DEPTH:
        return []
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip():
        model = node.value.strip()
        declared_in = "config" if in_config else "code"
        return [_use(model, infer_provider(model, provider_hint), declared_in, scope.rel_path, node, via)]
    if isinstance(node, ast.Name) and node.id in scope.bindings:
        return _resolve(scope.bindings[node.id], scope, via=via, provider_hint=provider_hint, in_config=in_config, depth=depth + 1)
    env_var, default = _env_lookup(node)
    if env_var:
        model = _string(default)
        provider = infer_provider(model, provider_hint) if model else provider_hint
        return [_use(model, provider, "env", scope.rel_path, node, _call_name(node) or "os.environ[]", env_var)]
    if isinstance(node, ast.Call):
        return _resolve_wrapper(node, scope, in_config=in_config, depth=depth)
    if isinstance(node, ast.Dict):
        return _resolve_config_dict(node, scope, via=via, provider_hint=provider_hint, depth=depth)
    if isinstance(node, (ast.List, ast.Tuple)):
        nested = (_resolve(item, scope, via=via, provider_hint=provider_hint, in_config=in_config, depth=depth + 1) for item in node.elts)
        return [use for uses in nested for use in uses]
    return []


def _resolve_wrapper(call: ast.Call, scope: ModelScope, *, in_config: bool, depth: int) -> list[AgentModelUse]:
    """``ChatOpenAI(model="gpt-4o")``, ``LLM("openai/gpt-4o")``, ``init_chat_model("openai:gpt-4o")``."""
    wrapper = _call_name(call.func).split(".")[-1]
    hint = _WRAPPER_PROVIDERS.get(wrapper, "")
    for keyword in _WRAPPER_MODEL_KEYWORDS:
        value = _keyword(call, keyword)
        if value is not None:
            return _resolve(value, scope, via=f"{wrapper}({keyword}=)", provider_hint=hint, in_config=in_config, depth=depth + 1)
    if wrapper in _POSITIONAL_MODEL_WRAPPERS and call.args:
        return _resolve(call.args[0], scope, via=f"{wrapper}(model)", provider_hint=hint, in_config=in_config, depth=depth + 1)
    return []


def _resolve_config_dict(node: ast.Dict, scope: ModelScope, *, via: str, provider_hint: str, depth: int) -> list[AgentModelUse]:
    """AutoGen ``{"model": ...}`` and ``{"config_list": [{"model": ...}]}``."""
    uses: list[AgentModelUse] = []
    for key, value in zip(node.keys, node.values, strict=False):
        if _string(key) in _CONFIG_MODEL_KEYS and value is not None:
            uses.extend(_resolve(value, scope, via=via, provider_hint=provider_hint, in_config=True, depth=depth + 1))
    return uses


def _env_lookup(node: ast.AST) -> tuple[str, ast.AST | None]:
    """``os.getenv("X", default)`` / ``os.environ.get("X")`` / ``os.environ["X"]`` → ``("X", default)``; the value is never read."""
    if isinstance(node, ast.Call) and _call_name(node.func) in _ENV_GETTERS and node.args:
        default = node.args[1] if len(node.args) > 1 else _keyword(node, "default")
        return _string(node.args[0]), default
    if isinstance(node, ast.Subscript) and _call_name(node.value) in {"os.environ", "environ"}:
        return _string(node.slice), None
    return "", None


def _crew_config_uses(call: ast.Call, scope: ModelScope) -> list[AgentModelUse]:
    """CrewAI ``Agent(config=self.agents_config["name"])`` reads ``llm`` from the crew's ``agents.yaml``."""
    value = _keyword(call, "config")
    if not isinstance(value, ast.Subscript) or not _call_name(value.value).endswith("agents_config"):
        return []
    key = _string(value.slice)
    entry = _crew_config(scope).get(key) if key else None
    if not entry:
        return []
    model, line = entry
    return [AgentModelUse(model, infer_provider(model), "config", scope.crew_config_path, line, f"agents.yaml:{key}.llm")]


def _crew_config(scope: ModelScope) -> dict[str, tuple[str, int]]:
    if scope.crew_config is None:
        scope.crew_config = {}
        path = _crew_config_path(scope)
        if path is not None:
            scope.crew_config_path = path.relative_to(scope.project_root.resolve()).as_posix()
            scope.crew_config = _read_crew_llms(path)
    return scope.crew_config


def _crew_config_path(scope: ModelScope) -> Path | None:
    """The ``agents_config`` path the crew class names (or CrewAI's default), only when it stays inside the project."""
    declared = next(
        (
            _string(node.value)
            for node in ast.walk(scope.tree)
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "agents_config" for t in node.targets)
        ),
        "",
    )
    root = scope.project_root.resolve()
    candidate = (scope.file_path.parent / (declared or _DEFAULT_CREW_AGENTS_CONFIG)).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    try:
        return candidate if candidate.stat().st_size <= _MAX_CONFIG_BYTES else None
    except OSError:
        return None


def _read_crew_llms(path: Path) -> dict[str, tuple[str, int]]:
    """``{agent_key: (llm, line)}`` from a CrewAI agents.yaml, with 1-based lines from the YAML node marks."""
    try:
        root = yaml.compose(path.read_text(encoding="utf-8", errors="replace"), Loader=yaml.SafeLoader)
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(root, yaml.MappingNode):
        return {}
    llms: dict[str, tuple[str, int]] = {}
    for agent_key, agent_node in root.value:
        if not isinstance(agent_node, yaml.MappingNode):
            continue
        for field_key, field_value in agent_node.value:
            if field_key.value == "llm" and isinstance(field_value, yaml.ScalarNode) and str(field_value.value).strip():
                llms[str(agent_key.value)] = (str(field_value.value).strip(), field_value.start_mark.line + 1)
    return llms


def _module_bindings(tree: ast.Module) -> dict[str, ast.expr]:
    """Module-level ``name = <expr>``; read only where a model is expected."""
    bindings: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            bindings.update({target.id: node.value for target in node.targets if isinstance(target, ast.Name)})
        elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
            bindings[node.target.id] = node.value
    return bindings


def _use(model: str, provider: str, declared_in: str, rel_path: str, node: ast.AST, via: str, env_var: str = "") -> AgentModelUse:
    return AgentModelUse(model, provider, declared_in, rel_path, getattr(node, "lineno", 1), via, env_var)


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _string(node: ast.AST | None) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""
