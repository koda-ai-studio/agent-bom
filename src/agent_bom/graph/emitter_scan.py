"""Static scan of the package for the modules that emit each graph node and edge kind.

Shared by the data-model doc generator and ``/v1/graph/schema`` so both report
the same producers. Reads source text only; nothing is imported from the
scanned modules.
"""

from __future__ import annotations

import ast
import dataclasses
import functools
from collections import defaultdict
from pathlib import Path

from agent_bom.core.entity_types import EntityType
from agent_bom.finding import FindingType
from agent_bom.graph.edge_evidence import SOURCE_TIERS
from agent_bom.graph.types import RelationshipType

PKG_DIR = Path(__file__).resolve().parents[1]

# Modules that define vocabularies or registries rather than emit graph content.
_REGISTRY_MODULES = frozenset(
    {
        "core/entity_types.py",
        "core/asset_types.py",
        "graph/types.py",
        "graph/relationship_specs.py",
        "graph/relationship_contract.py",
        "graph/edge_evidence.py",
        "graph/ocsf.py",
        "graph/container.py",
        "graph/compat.py",
    }
)
_NON_EMITTING_CALLS = frozenset(
    {"relationship_spec", "frozenset", "set", "tuple", "list", "dict", "isinstance", "RelationshipType", "EntityType", "len"}
)


@dataclasses.dataclass
class ScanResult:
    entity_emitters: dict[str, set[str]]
    rel_emitters: dict[str, set[str]]
    node_id_formats: dict[str, set[str]]
    collector_tiers: dict[str, set[str]]
    finding_refs: dict[str, set[str]]
    referenced_collectors: set[str]


def is_demo_module(module: str) -> bool:
    return any(part.startswith("demo") for part in module.split("/"))


def _aliases(nodes: list[ast.AST], name: str) -> set[str]:
    names = {name}
    for node in nodes:
        if isinstance(node, ast.ImportFrom):
            names.update(alias.asname for alias in node.names if alias.name == name and alias.asname)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) and node.value.id == name:
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _enum_member(node: ast.AST, aliases: set[str], members: set[str]) -> str | None:
    if isinstance(node, ast.Attribute) and node.attr == "value":
        node = node.value
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases and node.attr in members:
        return node.attr
    return None


def _emits(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Whether an enum-member reference feeds a value onward rather than testing one.

    Comparisons, membership sets, sequence tables and dict keys test or index;
    call arguments, dict values, assignments and returns pass the kind on to
    whatever builds the node or edge.
    """
    child, parent = node, parents.get(node)
    while isinstance(parent, ast.Attribute | ast.IfExp):
        child, parent = parent, parents.get(parent)
    if isinstance(parent, ast.keyword):
        parent = parents.get(parent)
        return isinstance(parent, ast.Call) and _call_name(parent) not in _NON_EMITTING_CALLS
    if isinstance(parent, ast.Call):
        return child is not parent.func and _call_name(parent) not in _NON_EMITTING_CALLS
    if isinstance(parent, ast.Dict):
        return any(value is child for value in parent.values)
    return isinstance(parent, ast.Assign | ast.AnnAssign | ast.Return)


def _collect_emitters(
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    module: str,
    aliases: set[str],
    members: set[str],
    into: dict[str, set[str]],
    enum: type[EntityType] | type[RelationshipType],
) -> None:
    for node in nodes:
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in aliases
            and node.attr in members
            and _emits(node, parents)
        ):
            into[enum[node.attr].value].add(module)


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def _template(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call) and _call_name(node) in {"stable_node_id", "canonical_graph_node_id", "canonical_id"}:
        return f"{_call_name(node)}(…) — UUIDv5"
    if not isinstance(node, ast.JoinedStr):
        return None
    parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant):
            parts.append(str(value.value))
            continue
        expr = value.value if isinstance(value, ast.FormattedValue) else value
        if isinstance(expr, ast.Name):
            parts.append(f"{{{expr.id}}}")
        elif isinstance(expr, ast.Attribute):
            parts.append(f"{{{expr.attr}}}")
        else:
            parts.append("{…}")
    text = "".join(parts)
    return text if len(text) <= 90 else text[:87] + "…"


_Scopes = dict[tuple[ast.AST | None, str], list[tuple[int, str]]]


def _scope_of(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST | None:
    scope = parents.get(node)
    while scope is not None and not isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef):
        scope = parents.get(scope)
    return scope


def _named_templates(nodes: list[ast.AST], parents: dict[ast.AST, ast.AST]) -> _Scopes:
    """(innermost function, local name) -> ``(line, template)`` for ``name = f"…"`` bindings."""
    named: _Scopes = defaultdict(list)
    for node in nodes:
        if isinstance(node, ast.Assign) and (template := _template(node.value)):
            scope = _scope_of(node, parents)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    named[(scope, target.id)].append((node.lineno, template))
    return named


def _resolve_id_name(call: ast.Call, name: str, parents: dict[ast.AST, ast.AST], named: _Scopes) -> set[str]:
    """The nearest preceding ``name = f"…"`` in the innermost enclosing function."""
    scope = _scope_of(call, parents)
    bindings = [b for b in named.get((scope, name), []) if b[0] <= call.lineno] if scope is not None else []
    return {max(bindings)[1]} if bindings else set()


def _module_strings(tree: ast.Module) -> dict[str, str]:
    consts: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            consts.update({t.id: node.value.value for t in node.targets if isinstance(t, ast.Name)})
    return consts


_SCAN_MARKERS = ("EntityType", "RelationshipType", "UnifiedNode", "edge_evidence")


def _record_finding_ref(
    node: ast.AST, module: str, finding_alias: set[str], finding_values: set[str], finding_members: set[str], result: ScanResult
) -> None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in finding_values:
        result.finding_refs[node.value].add(module)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id in finding_alias and node.attr in finding_members:
            result.finding_refs[FindingType[node.attr].value].add(module)


def _record_call(
    node: ast.Call,
    consts: dict[str, str],
    ent_alias: set[str],
    entity_members: set[str],
    parents: dict[ast.AST, ast.AST],
    named_ids: _Scopes,
    result: ScanResult,
) -> None:
    name = _call_name(node)
    if name == "edge_evidence" and len(node.args) >= 2 and isinstance(node.args[0], ast.Constant):
        tier_node = node.args[1]
        tier = tier_node.value if isinstance(tier_node, ast.Constant) else consts.get(getattr(tier_node, "id", ""), "")
        if isinstance(node.args[0].value, str) and tier:
            result.collector_tiers[node.args[0].value].add(str(tier))
    if name != "UnifiedNode":
        return
    kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
    member = _enum_member(kwargs.get("entity_type", ast.Constant(None)), ent_alias, entity_members)
    id_node = kwargs.get("id")
    if isinstance(id_node, ast.Name):
        templates = _resolve_id_name(node, id_node.id, parents, named_ids)
    else:
        templates = {t for t in [_template(id_node)] if t} if id_node is not None else set()
    if member:
        result.node_id_formats[EntityType[member].value].update(templates)


@functools.cache
def scan_source(pkg_dir: Path | None = None) -> ScanResult:
    """Statically find which modules emit each entity and relationship kind."""
    base = pkg_dir or PKG_DIR
    entity_members = {e.name for e in EntityType}
    rel_members = {r.name for r in RelationshipType}
    finding_values = {f.value for f in FindingType}
    finding_members = {f.name for f in FindingType}
    result = ScanResult(defaultdict(set), defaultdict(set), defaultdict(set), defaultdict(set), defaultdict(set), set())
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        module = path.relative_to(base).as_posix()
        text = path.read_text(encoding="utf-8")
        if path.name != "edge_evidence.py":
            result.referenced_collectors.update(c for c in SOURCE_TIERS if f'"{c}' in text)
        in_graph = module.startswith("graph/")
        if not any(marker in text for marker in _SCAN_MARKERS) and not in_graph:
            continue
        tree = ast.parse(text, filename=str(path))
        nodes = list(ast.walk(tree))
        parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
        ent_alias, rel_alias = _aliases(nodes, "EntityType"), _aliases(nodes, "RelationshipType")
        finding_alias = _aliases(nodes, "FindingType")
        consts = _module_strings(tree)
        named_ids = _named_templates(nodes, parents)
        if module not in _REGISTRY_MODULES:
            _collect_emitters(nodes, parents, module, ent_alias, entity_members, result.entity_emitters, EntityType)
            _collect_emitters(nodes, parents, module, rel_alias, rel_members, result.rel_emitters, RelationshipType)
        for node in nodes:
            if in_graph:
                _record_finding_ref(node, module, finding_alias, finding_values, finding_members, result)
            if isinstance(node, ast.Call):
                _record_call(node, consts, ent_alias, entity_members, parents, named_ids, result)
    return result


@functools.cache
def production_emitters(*, relationships: bool) -> dict[str, list[str]]:
    """Kind -> non-demo modules the scan found emitting it."""
    scan = scan_source()
    found = scan.rel_emitters if relationships else scan.entity_emitters
    result = {kind: sorted(m for m in modules if not is_demo_module(m)) for kind, modules in found.items()}
    return {kind: modules for kind, modules in result.items() if modules}
