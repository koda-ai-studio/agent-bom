"""Cross-source correlation page for the graph data-model generator.

Reads the merge rules out of ``graph/correlation.py`` ``correlation_identity``
(the branch per entity-type set, the attribute keys each branch accepts and the
basis label it records), the identity helpers in ``canonical_ids``, the finding
row projection in ``evidence/finding_node_ids.py`` and the cloud alias index in
``graph/resource_aliases.py``. Branches and keys come from a static AST read;
the entity-type sets are imported from the module that owns them.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from collections import defaultdict
from pathlib import Path
from typing import Any

from agent_bom import canonical_ids
from agent_bom.core.asset_types import _ASSET_TYPE_ALIASES
from agent_bom.core.entity_types import EntityType
from agent_bom.finding import FindingSource
from agent_bom.graph import correlation as correlation_module
from agent_bom.graph.edge_evidence import SOURCE_TIERS

DOC = "docs/graph/data-model/correlation.md"
PKG_DIR = Path(__file__).resolve().parents[1] / "src" / "agent_bom"
IDENTITY_FUNCTION = "correlation_identity"
FALLBACK_LABEL = "every other entity type"


@dataclasses.dataclass
class Branch:
    label: str
    entity_types: list[str]
    keys: list[str]
    bases: list[str]
    helpers: list[str]
    provider_override: bool = False


def _module_tree(relative: str) -> ast.Module:
    return ast.parse((PKG_DIR / relative).read_text(encoding="utf-8"))


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise SystemExit(f"{name}() not found; update scripts/graph_data_model_correlation.py")


def _call_name(node: ast.Call) -> str:
    func = node.func
    return func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""


def _entity_types_in(test: ast.AST) -> tuple[list[str], bool]:
    """Entity-type values a branch condition selects, and whether it keys on the provider instead."""
    found: set[str] = set()
    provider = False
    for node in ast.walk(test):
        if isinstance(node, ast.Name) and isinstance(getattr(correlation_module, node.id, None), frozenset):
            found |= set(getattr(correlation_module, node.id))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "EntityType":
            found.add(EntityType[node.attr].value)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value not in found:
            provider = provider or node.value in {"snowflake"}
    return sorted(found), provider


def _string_tuple(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Tuple) and node.elts and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts):
        return [str(e.value) for e in node.elts if isinstance(e, ast.Constant)]
    return []


def _returned_bases(node: ast.Return) -> list[str]:
    values = [node.value.body, node.value.orelse] if isinstance(node.value, ast.IfExp) else [node.value]
    return [
        v.elts[2].value
        for v in values
        if isinstance(v, ast.Tuple) and len(v.elts) == 3 and isinstance(v.elts[2], ast.Constant) and isinstance(v.elts[2].value, str)
    ]


_KEY_TAKING_HELPERS = frozenset({"exact_attribute_identity", "snapshot_scoped_identity"})


def _branch_facts(body: list[ast.stmt], helpers_tree: ast.Module) -> tuple[list[str], list[str], list[str]]:
    """Attribute keys, basis labels and identity helpers reached from a branch body."""
    keys: list[str] = []
    bases: list[str] = []
    helpers: list[str] = []
    local = {n.name for n in helpers_tree.body if isinstance(n, ast.FunctionDef)}

    def add(into: list[str], values: list[str]) -> None:
        into += [v for v in values if v not in into]

    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Return):
                add(bases, _returned_bases(node))
            if isinstance(node, ast.comprehension | ast.For):
                add(keys, _string_tuple(node.iter))
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node).lstrip("_")
            func = node.func
            if (
                name == "get"
                and isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "attributes"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value != "cloud_provider"
            ):
                add(keys, [node.args[0].value])
            for kw in node.keywords:
                if kw.arg == "keys":
                    add(keys, _string_tuple(kw.value))
                if kw.arg == "basis" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    add(bases, [kw.value.value])
            if name in {"PackageURL", "from_string"}:
                add(keys, ["purl"])
            if name != IDENTITY_FUNCTION and name.endswith(("_identity", "_occurrence")) and name not in helpers:
                helpers.append(name)
                if name in local and name not in _KEY_TAKING_HELPERS:
                    k, bs, _h = _branch_facts(_function(helpers_tree, name).body, helpers_tree)
                    add(keys, k)
                    add(bases, bs)
    return keys, bases, helpers


def identity_branches() -> list[Branch]:
    """One entry per top-level ``if`` in ``correlation_identity``, then the fallback."""
    tree = _module_tree("graph/correlation.py")
    scope_tree = _module_tree("graph/correlation_scope.py")
    func = _function(tree, IDENTITY_FUNCTION)
    branches: list[Branch] = []
    tail: list[ast.stmt] = []
    for stmt in func.body:
        if isinstance(stmt, ast.If):
            types, provider = _entity_types_in(stmt.test)
            keys, bases, helpers = _branch_facts(stmt.body, scope_tree)
            label = ast.unparse(stmt.test).replace("_RUNTIME_ENTITY_TYPES", "runtime types")
            branches.append(Branch(label, [] if provider else types, keys, bases, helpers, provider))
        elif not isinstance(stmt, ast.Expr):
            tail.append(stmt)
    keys, bases, helpers = _branch_facts(tail, scope_tree)
    claimed = {t for b in branches for t in b.entity_types}
    rest = sorted(e.value for e in EntityType if e.value not in claimed)
    branches.append(Branch(FALLBACK_LABEL, rest, keys, bases, helpers))
    return branches


def entity_branch(branches: list[Branch]) -> dict[str, Branch]:
    found: dict[str, Branch] = {}
    for branch in branches:
        for entity in branch.entity_types:
            found.setdefault(entity, branch)
    return found


def canonical_functions() -> dict[str, list[str]]:
    """Entity type -> ``canonical_ids`` functions whose name ends in that type (``canonical_<…>_<type>_id``)."""
    values = {e.value for e in EntityType}
    found: dict[str, list[str]] = defaultdict(list)
    for name, func in sorted(inspect.getmembers(canonical_ids, inspect.isfunction)):
        if not name.startswith("canonical_") or not name.endswith("_id") or func.__module__ != canonical_ids.__name__:
            continue
        stem = name.removeprefix("canonical_").removesuffix("_id")
        for size in (2, 1):
            candidate = "_".join(stem.split("_")[-size:])
            if candidate in values:
                found[candidate].append(name)
                break
    return found


def _template(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            str(v.value) if isinstance(v, ast.Constant) else "{" + ast.unparse(v.value) + "}"  # type: ignore[attr-defined]
            for v in node.values
        )
    return None


def finding_node_templates() -> list[tuple[str, str]]:
    """``(function, returned id template)`` for the finding-row projection."""
    tree = _module_tree("evidence/finding_node_ids.py")
    rows = []
    for func in tree.body:
        if isinstance(func, ast.FunctionDef) and func.name.endswith("node_id"):
            for node in ast.walk(func):
                if isinstance(node, ast.Return) and node.value is not None and (text := _template(node.value)):
                    rows.append((func.name, text))
    return rows


def alias_entity_types() -> list[str]:
    tree = _module_tree("graph/resource_aliases.py")
    return sorted(
        {
            EntityType[n.attr].value
            for n in ast.walk(tree)
            if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name)
            and n.value.id == "EntityType"
            and n.attr in EntityType.__members__
        }
    )


def _literal_assign(relative: str, name: str) -> Any:
    for node in _module_tree(relative).body:
        if isinstance(node, ast.AnnAssign | ast.Assign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == name for t in targets) and node.value is not None:
                return ast.literal_eval(node.value)
    return None


def trace_vendors() -> list[str]:
    tree = _module_tree("trace_connectors.py")
    return sorted(
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        and all(isinstance(t, ast.Name) and t.id.isupper() and not t.id.startswith("_") for t in node.targets)
    )


def _docline(relative: str) -> str:
    return (ast.get_docstring(_module_tree(relative)) or "").splitlines()[0]


def not_correlated(branches: list[Branch], node_id_formats: dict[str, set[str]]) -> list[str]:
    """Fallback-only entity types with no canonical function and no canonical node id format."""
    by_entity = entity_branch(branches)
    functions = canonical_functions()
    return [
        entity
        for entity in sorted(e.value for e in EntityType)
        if by_entity[entity].label == FALLBACK_LABEL
        and not functions.get(entity)
        and not any("UUIDv5" in fmt for fmt in node_id_formats.get(entity, set()))
    ]


def _code(value: str) -> str:
    return f"`{value}`"


def _codes(values: list[str]) -> str:
    return ", ".join(_code(v) for v in values) or "—"


def _mermaid(branches: list[Branch]) -> list[str]:
    providers = sorted(_literal_assign("cloud/__init__.py", "_PROVIDERS") or {})
    tiers: dict[str, int] = defaultdict(int)
    for tier in SOURCE_TIERS.values():
        tiers[tier] += 1
    lines = [
        "```mermaid",
        "flowchart LR",
        '  subgraph sources["Sources"]',
        f'    cloud["Cloud and platform providers<br/>{len(providers)} built in"]',
        f'    traces["Trace connectors<br/>{", ".join(trace_vendors())}"]',
        f'    findings["Finding sources<br/>{len(FindingSource)} FindingSource values"]',
        f'    collectors["Edge collectors<br/>{len(SOURCE_TIERS)} in SOURCE_TIERS"]',
        "  end",
        '  subgraph normalize["Normalization"]',
        f'    assettype["asset_type → EntityType<br/>{len(_ASSET_TYPE_ALIASES)} spellings"]',
        '    findingrow["finding row → finding node<br/>finding_row_node_id"]',
        "  end",
        f'  subgraph identity["{IDENTITY_FUNCTION}"]',
    ]
    for i, branch in enumerate(branches):
        what = "cloud_provider = snowflake" if branch.provider_override else f"{len(branch.entity_types)} entity types"
        basis = ", ".join(branch.bases[:3]) + (" …" if len(branch.bases) > 3 else "")
        lines.append(f'    b{i}["{what}<br/>{basis}"]')
    lines += [
        "  end",
        '  merged["merged node per (entity_type, identity)<br/>graph_correlation_runs / merged_nodes"]',
        "  cloud --> assettype",
        "  traces --> assettype",
        "  collectors --> assettype",
        "  findings --> findingrow",
        "  assettype --> identity",
        "  findingrow --> identity",
        "  identity --> merged",
        "```",
    ]
    return lines


def render(node_id_formats: dict[str, set[str]], generator: str) -> list[str]:
    branches = identity_branches()
    by_entity = entity_branch(branches)
    functions = canonical_functions()
    providers = sorted(_literal_assign("cloud/__init__.py", "_PROVIDERS") or {})
    out = [
        "# Cross-source correlation",
        "",
        f"> Generated from the code by `{generator}`. Do not edit by hand: re-run the",
        "> generator and commit the result. CI runs it with `--check` and fails on drift.",
        "",
        "How records from different scanners, providers and environments become one graph node. "
        f"The merge rule is `agent_bom.graph.correlation.{IDENTITY_FUNCTION}`: it returns "
        "`(entity_type, identity, basis)`, and observations with the same pair merge. "
        "When no exact identity is present the identity is snapshot-scoped (`snapshot:<scan_id>:<node canonical id>`), "
        "so the record never merges across scans. Back to the [data model](../DATA_MODEL.md).",
        "",
        *_mermaid(branches),
        "",
        "## Sources",
        "",
        f"- Cloud and platform providers (`cloud/__init__.py` `_PROVIDERS`): {_codes(providers)}",
        f"- Trace connectors (`trace_connectors.py`): {_codes(trace_vendors())}",
        f"- Finding sources (`agent_bom.finding.FindingSource`): {_codes([f.value for f in FindingSource])}",
        f"- Edge collectors (`graph/edge_evidence.py` `SOURCE_TIERS`): {_codes(sorted(SOURCE_TIERS))}",
        "",
        "## Normalization",
        "",
        "`core/asset_types.py` maps a vendor or scanner `asset_type` to an entity type "
        + "(full table in the [data model](../DATA_MODEL.md#asset-type-normalization)). Spellings per entity type:",
        "",
        "| Entity | Accepted `asset_type` spellings |",
        "|---|---|",
    ]
    spellings: dict[str, list[str]] = defaultdict(list)
    for alias, entity in _ASSET_TYPE_ALIASES.items():
        if alias != entity.value:
            spellings[entity.value].append(alias)
    out += [f"| {_code(e)} | {_codes(sorted(a))} |" for e, a in sorted(spellings.items())]
    out += [
        "",
        "A finding row becomes a finding node through `evidence/finding_node_ids.py`:",
        "",
        "| Function | Node id |",
        "|---|---|",
        *(f"| {_code(f)} | {_code(t)} |" for f, t in finding_node_templates()),
        "",
        f"`graph/resource_aliases.py` ({_docline('graph/resource_aliases.py')}) resolves a finding's resource "
        f"reference to an existing node of type {_codes(alias_entity_types())} by provider-native id, typed name or "
        "unambiguous name, scoped to provider and account.",
        "",
        f"`api/auto_correlation.py`: {_docline('api/auto_correlation.py')}",
        "",
        "## Identity rules",
        "",
        f"Top-level branches of `{IDENTITY_FUNCTION}`, in evaluation order. The first branch whose condition holds decides; "
        "within a branch the first non-empty key wins.",
        "",
        "| # | Condition | Entity types | Identity keys | Basis recorded | Helpers |",
        "|---|---|---|---|---|---|",
    ]
    for i, b in enumerate(branches):
        types = "any, when the provider matches" if b.provider_override else _codes(b.entity_types)
        out.append(f"| {i + 1} | {_code(b.label)} | {types} | {_codes(b.keys)} | {_codes(b.bases)} | {_codes(b.helpers)} |")
    out += [
        "",
        "## Per entity type",
        "",
        "*Canonical id functions* are `agent_bom.canonical_ids` functions named for the type. "
        + "*Node id formats* are the statically detected `UnifiedNode(id=…)` templates.",
        "",
        "| Entity | Merge branch | Canonical id functions | Node id formats |",
        "|---|---|---|---|",
    ]
    for entity in sorted(e.value for e in EntityType):
        b = by_entity[entity]
        formats = sorted(node_id_formats.get(entity, set()))
        shown = _codes(formats[:3]) + (f" (+{len(formats) - 3})" if len(formats) > 3 else "")
        out.append(f"| {_code(entity)} | {branches.index(b) + 1} | {_codes(functions.get(entity, []))} | {shown} |")
    missing = not_correlated(branches, node_id_formats)
    out += [
        "",
        "## Not correlated across sources yet",
        "",
        "Entity types that reach only the generic fallback branch, have no `canonical_ids` function and no "
        + "detected UUIDv5 node id. Two sources describing the same thing merge only if each stamps the same "
        + "`canonical_id` / `stable_id` attribute; otherwise each record stays snapshot-scoped.",
        "",
        *(f"- {_code(e)}" for e in missing),
        "",
    ]
    return out
