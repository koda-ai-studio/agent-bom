"""Python eval harnesses read from source: deepeval, ragas, Inspect, LangSmith and the OpenAI Evals API.

The scanned code is parsed, never imported. Safety and quality labels come only
from what the code names: deepeval safety metric classes or a deepteam
red-team, ragas harmfulness/maliciousness critiques, or an Inspect task built
on a known safety benchmark. Judge models passed to a metric are graders, not
the system under test, and are never recorded as a target.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.ai_components.eval_linking import AgentIndex, resolve_module_file
from agent_bom.ai_components.eval_models import (
    PURPOSE_QUALITY,
    PURPOSE_SAFETY,
    PURPOSE_UNKNOWN,
    EvalSuite,
    EvalTarget,
)

PYTHON_MARKERS: tuple[str, ...] = ("deepeval", "deepteam", "ragas", "inspect_ai", "inspect_evals", "langsmith", "evals.create")

DEEPEVAL_SAFETY_METRICS = frozenset(
    {"BiasMetric", "ToxicityMetric", "PIILeakageMetric", "RoleViolationMetric", "MisuseMetric", "NonAdviceMetric"}
)
DEEPEVAL_QUALITY_METRICS = frozenset(
    {
        "AnswerRelevancyMetric",
        "FaithfulnessMetric",
        "ContextualRelevancyMetric",
        "ContextualPrecisionMetric",
        "ContextualRecallMetric",
        "HallucinationMetric",
        "SummarizationMetric",
        "GEval",
        "ConversationalGEval",
        "DAGMetric",
        "TaskCompletionMetric",
        "ToolCorrectnessMetric",
        "ArgumentCorrectnessMetric",
        "StepEfficiencyMetric",
        "PlanAdherenceMetric",
        "PlanQualityMetric",
        "JsonCorrectnessMetric",
        "PromptAlignmentMetric",
        "RoleAdherenceMetric",
        "KnowledgeRetentionMetric",
        "ConversationCompletenessMetric",
        "ConversationRelevancyMetric",
    }
)
RAGAS_SAFETY_METRICS = frozenset({"harmfulness", "maliciousness"})
RAGAS_QUALITY_METRICS = frozenset(
    {
        "faithfulness",
        "answer_relevancy",
        "answer_correctness",
        "answer_similarity",
        "context_precision",
        "context_recall",
        "context_entity_recall",
        "Faithfulness",
        "AnswerRelevancy",
        "ResponseRelevancy",
        "AnswerCorrectness",
        "FactualCorrectness",
        "ContextPrecision",
        "ContextRecall",
        "LLMContextPrecisionWithReference",
        "LLMContextPrecisionWithoutReference",
        "LLMContextRecall",
        "NoiseSensitivity",
    }
)
# inspect_evals packages that are safety, misuse or red-team benchmarks.
INSPECT_SAFETY_BENCHMARKS = frozenset(
    {"agentharm", "strong_reject", "wmdp", "xstest", "cyberseceval_2", "cyberseceval_3", "b3", "mask", "makemesay"}
)
_LANGSMITH_EVALUATE = frozenset({"evaluate", "aevaluate"})
_MAX_FOLLOW_DEPTH = 3


@dataclass
class _Module:
    root: Path
    path: Path
    rel: str
    tree: ast.Module
    index: AgentIndex
    scope: str
    imports: dict[str, tuple[str, str, int]] = field(default_factory=dict)
    assigns: dict[str, list[ast.expr]] = field(default_factory=dict)
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = (node.module or "", alias.name, node.level)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports[alias.asname or alias.name.split(".")[0]] = (alias.name, "", 0)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.assigns.setdefault(target.id, []).append(node.value)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)

    def import_roots(self) -> set[str]:
        return {module.split(".")[0] for module, _name, level in self.imports.values() if module and not level}

    def origin(self, name: str) -> str:
        module, original, _level = self.imports.get(name, ("", "", 0))
        return f"{module}.{original}" if original else module

    def agent_ids(self, expr: ast.AST, depth: int = 0, seen: set[str] | None = None) -> tuple[set[str], list[str]]:
        """Framework agents an expression is built from, with the import evidence that resolved them."""
        seen = seen if seen is not None else set()
        ids: set[str] = set()
        evidence: list[str] = []
        for node in ast.walk(expr):
            if not isinstance(node, ast.Name) or node.id in seen:
                continue
            seen.add(node.id)
            found, why = self._resolve_name(node.id, depth, seen)
            ids |= found
            evidence += why
        return ids, evidence

    def _resolve_name(self, name: str, depth: int, seen: set[str]) -> tuple[set[str], list[str]]:
        if name in self.imports:
            module, original, level = self.imports[name]
            module_file = resolve_module_file(self.root, self.path, module, level) if original else None
            if module_file:
                found = set(self.index.symbol_in_file(self.root, module_file, original))
                return found, [f"imports {original} from {module_file}"] if found else []
            return set(), []
        local = set(self.index.symbol_in_file(self.root, self.rel, name))
        if local:
            return local, [f"defines {name} in {self.rel}"]
        if depth >= _MAX_FOLLOW_DEPTH:
            return set(), []
        ids: set[str] = set()
        evidence: list[str] = []
        sources: list[ast.AST] = list(self.assigns.get(name, []))
        if name in self.functions:
            sources.append(self.functions[name])
        for source in sources:
            found, why = self.agent_ids(source, depth + 1, seen)
            ids |= found
            evidence += why
        return ids, evidence


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _keyword(node: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in node.keywords if kw.arg == name), None)


def _literal_strings(node: ast.expr | None) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        return [elt.value for elt in node.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
    return []


def _agent_target(module: _Module, expr: ast.expr, line: int, label: str) -> EvalTarget | None:
    ids, evidence = module.agent_ids(expr)
    ref = _dotted(expr.func if isinstance(expr, ast.Call) else expr) or label
    if ids:
        return EvalTarget("agent", ref, line, "; ".join(dict.fromkeys(evidence)) or label, tuple(sorted(ids)))
    return None


def _calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _deepeval(module: _Module) -> list[EvalSuite]:
    roots = module.import_roots()
    calls = _calls(module.tree)
    metrics = {_call_name(call) for call in calls if module.origin(_call_name(call)).startswith("deepeval")}
    safety = sorted(metrics & DEEPEVAL_SAFETY_METRICS)
    quality = sorted(metrics & DEEPEVAL_QUALITY_METRICS)
    evidence: list[str] = []
    if "deepteam" in roots:
        evidence.append("deepteam red-teaming")
    if safety:
        evidence.append("deepeval safety metrics: " + ", ".join(safety))
    if evidence:
        purpose = PURPOSE_SAFETY
    elif quality:
        purpose, evidence = PURPOSE_QUALITY, ["deepeval quality metrics: " + ", ".join(quality)]
    else:
        purpose = PURPOSE_UNKNOWN
    targets: dict[str, EvalTarget] = {}
    for call in calls:
        name = _call_name(call)
        expr = _keyword(call, "actual_output") if name.endswith("TestCase") else _keyword(call, "model_callback")
        if expr is None:
            continue
        target = _agent_target(module, expr, call.lineno, name)
        if target is not None:
            targets.setdefault(",".join(target.agent_ids), target)
    line = min((call.lineno for call in calls if _call_name(call) in metrics), default=1)
    return [
        EvalSuite(
            "deepeval", Path(module.rel).stem, module.rel, line, purpose, tuple(evidence), tuple(targets.values()), scope=module.scope
        )
    ]


def _ragas(module: _Module) -> list[EvalSuite]:
    metric_names = {local for local, (mod, _orig, _lvl) in module.imports.items() if mod.startswith("ragas.metrics") or mod == "ragas"} | {
        _call_name(call) for call in _calls(module.tree) if module.origin(_call_name(call)).startswith("ragas.metrics")
    }
    originals = {module.imports[name][1] or name for name in metric_names if name in module.imports}
    safety = sorted(originals & RAGAS_SAFETY_METRICS)
    quality = sorted(originals & RAGAS_QUALITY_METRICS)
    evidence: tuple[str, ...] = ()
    purpose = PURPOSE_UNKNOWN
    if safety:
        purpose, evidence = PURPOSE_SAFETY, ("ragas safety critiques: " + ", ".join(safety),)
    elif quality:
        purpose, evidence = PURPOSE_QUALITY, ("ragas quality metrics: " + ", ".join(quality),)
    line = next((call.lineno for call in _calls(module.tree) if module.origin(_call_name(call)) == "ragas.evaluate"), 1)
    return [EvalSuite("ragas", Path(module.rel).stem, module.rel, line, purpose, evidence, scope=module.scope)]


def _is_task(decorator: ast.expr, module: _Module) -> bool:
    node = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = _dotted(node)
    return name == "inspect_ai.task" or (name == "task" and module.origin("task") == "inspect_ai.task")


def _inspect(module: _Module) -> list[EvalSuite]:
    suites: list[EvalSuite] = []
    eval_models = _inspect_eval_models(module)
    for func in module.functions.values():
        if not any(_is_task(decorator, module) for decorator in func.decorator_list):
            continue
        benchmarks = sorted(
            {
                module.imports[_call_name(call)][0].split(".")[1]
                for call in _calls(func)
                if module.imports.get(_call_name(call), ("", "", 0))[0].startswith("inspect_evals.")
            }
        )
        safety = [name for name in benchmarks if name in INSPECT_SAFETY_BENCHMARKS]
        purpose, evidence = (PURPOSE_SAFETY, ("inspect_evals safety benchmark: " + ", ".join(safety),)) if safety else (PURPOSE_UNKNOWN, ())
        targets: list[EvalTarget] = [
            EvalTarget("model", ref, line, "inspect eval(model=...)") for ref, line in eval_models.get(func.name, [])
        ]
        for call in _calls(func):
            if _call_name(call) != "Task":
                continue
            targets += [
                EvalTarget("model", ref, call.lineno, "inspect Task(model=...)") for ref in _literal_strings(_keyword(call, "model"))
            ]
            solver = _keyword(call, "solver")
            agent = _agent_target(module, solver, call.lineno, "solver") if solver is not None else None
            if agent is not None:
                targets.append(agent)
        suites.append(EvalSuite("inspect", func.name, module.rel, func.lineno, purpose, evidence, tuple(targets), scope=module.scope))
    return suites


def _inspect_eval_models(module: _Module) -> dict[str, list[tuple[str, int]]]:
    """Model ids an ``eval()``/``eval_set()`` call runs named tasks against."""
    models: dict[str, list[tuple[str, int]]] = {}
    for call in _calls(module.tree):
        name = _call_name(call)
        if (
            name not in {"eval", "eval_set"}
            or not module.origin(name).startswith("inspect_ai")
            and _dotted(call.func) != f"inspect_ai.{name}"
        ):
            continue
        refs = _literal_strings(_keyword(call, "model"))
        tasks = call.args[0] if call.args else _keyword(call, "tasks")
        task_names = {node.id for node in ast.walk(tasks) if isinstance(node, ast.Name)} if tasks is not None else set()
        for task_name in task_names:
            for ref in refs:
                models.setdefault(task_name, []).append((ref, call.lineno))
    return models


def _langsmith(module: _Module) -> list[EvalSuite]:
    suites: list[EvalSuite] = []
    datasets: dict[str, int] = {}
    for call in _calls(module.tree):
        name = _call_name(call)
        if name == "create_dataset":
            for ref in _literal_strings(_keyword(call, "dataset_name") or (call.args[0] if call.args else None)):
                datasets.setdefault(ref, call.lineno)
            continue
        is_method = isinstance(call.func, ast.Attribute)
        if name not in _LANGSMITH_EVALUATE or (not is_method and not module.origin(name).startswith("langsmith")):
            continue
        data = _literal_strings(_keyword(call, "data"))
        prefix = _literal_strings(_keyword(call, "experiment_prefix"))
        label = (data or prefix or [f"{Path(module.rel).stem}:{call.lineno}"])[0]
        expr = call.args[0] if call.args else _keyword(call, "target")
        target = _agent_target(module, expr, call.lineno, "target") if expr is not None else None
        suites.append(EvalSuite("langsmith", label[:200], module.rel, call.lineno, targets=(target,) if target else (), scope=module.scope))
    named = {suite.name for suite in suites}
    suites += [
        EvalSuite("langsmith", name[:200], module.rel, line, scope=module.scope) for name, line in datasets.items() if name not in named
    ]
    return suites


def _openai_evals_api(module: _Module) -> list[EvalSuite]:
    suites: list[EvalSuite] = []
    for call in _calls(module.tree):
        if not _dotted(call.func).endswith("evals.create"):
            continue
        label = (_literal_strings(_keyword(call, "name")) or [f"{Path(module.rel).stem}:{call.lineno}"])[0]
        suites.append(EvalSuite("openai-evals", label[:200], module.rel, call.lineno, scope=module.scope))
    return suites


def parse_python_evals(root: Path, path: Path, tree: ast.Module, index: AgentIndex, scope: str) -> list[EvalSuite]:
    module = _Module(root, path, path.relative_to(root).as_posix(), tree, index, scope)
    roots = module.import_roots()
    suites: list[EvalSuite] = []
    if roots & {"deepeval", "deepteam"}:
        suites += _deepeval(module)
    if "ragas" in roots:
        suites += _ragas(module)
    if roots & {"inspect_ai", "inspect_evals"}:
        suites += _inspect(module)
    if "langsmith" in roots:
        suites += _langsmith(module)
    if "openai" in roots:
        suites += _openai_evals_api(module)
    return suites
