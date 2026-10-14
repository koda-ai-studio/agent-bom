#!/usr/bin/env python3
"""Generate the security-graph data-model reference from the live code.

Reads the entity and relationship enums, the relationship registry, the edge
evidence collector registry, the finding enums, the asset-type normalization
table and the analysis edge sets, plus a static scan of ``src/agent_bom`` for
the modules that emit each node and edge kind. Writes:

- docs/graph/DATA_MODEL.md — overview diagram and catalogs
- docs/graph/data-model/relationships.md — allowed pairs and emitting modules
- docs/graph/data-model/entities.md — emitting modules and node id formats

Usage:
    python scripts/generate_graph_data_model.py            # regenerate
    python scripts/generate_graph_data_model.py --check    # CI drift guard
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import functools
import importlib
import inspect
import re
import sys
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
PKG_DIR = SRC_ROOT / "agent_bom"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agent_bom import canonical_ids  # noqa: E402
from agent_bom.core.asset_types import _ASSET_TYPE_ALIASES  # noqa: E402
from agent_bom.core.entity_types import EntityType  # noqa: E402
from agent_bom.finding import FindingSource, FindingType  # noqa: E402
from agent_bom.graph import (  # noqa: E402
    attack_path_fusion,
    attack_path_mitre,
    credential_reach,
    dependency_reach,
    path_derivation,
    toxic_findings,
)
from agent_bom.graph.container import ENTITY_LEGEND  # noqa: E402
from agent_bom.graph.edge_evidence import EDGE_EVIDENCE_TIERS, LEGACY_TIER, SOURCE_TIERS  # noqa: E402
from agent_bom.graph.ocsf import ENTITY_OCSF_MAP, FINDING_ENTITY_TYPES  # noqa: E402
from agent_bom.graph.relationship_specs import RELATIONSHIP_SPECS, RelationshipSpec, TraversalClass  # noqa: E402
from agent_bom.graph.types import GraphSemanticLayer, RelationshipType  # noqa: E402

MAIN_DOC = "docs/graph/DATA_MODEL.md"
REL_DOC = "docs/graph/data-model/relationships.md"
ENTITY_DOC = "docs/graph/data-model/entities.md"
GENERATOR = "scripts/generate_graph_data_model.py"
LINE_CEILING = 1000

# Presentation grouping of the code's semantic layers into diagram domains.
# A new layer without a domain fails generation instead of vanishing.
DOMAINS: tuple[tuple[str, str, tuple[GraphSemanticLayer, ...]], ...] = (
    ("identity", "Identity and access", (GraphSemanticLayer.USER, GraphSemanticLayer.IDENTITY)),
    (
        "ai",
        "AI and agents",
        (
            GraphSemanticLayer.ORCHESTRATION,
            GraphSemanticLayer.MCP_SERVER,
            GraphSemanticLayer.TOOL,
            GraphSemanticLayer.RUNTIME_EVIDENCE,
            GraphSemanticLayer.APP,
        ),
    ),
    ("supply", "Code and supply chain", (GraphSemanticLayer.PACKAGE, GraphSemanticLayer.CODE, GraphSemanticLayer.CI)),
    ("cloud", "Cloud, infrastructure and data", (GraphSemanticLayer.ASSET, GraphSemanticLayer.INFRA, GraphSemanticLayer.API_GATEWAY)),
    ("findings", "Findings", (GraphSemanticLayer.FINDING,)),
)

# Edge sets the analyses walk, read from the modules that own them.
ANALYSES: tuple[tuple[str, str, str, frozenset[str]], ...] = (
    (
        "FU",
        "Attack-path fusion",
        "graph/attack_path_fusion.py `_TRAVERSABLE_RELS`",
        frozenset(r.value for r in attack_path_fusion._TRAVERSABLE_RELS),
    ),
    ("CR", "Credential reach", "graph/credential_reach.py `_CHAIN`", frozenset(r.value for r in credential_reach._CHAIN)),
    (
        "BR",
        "Dependency reach (blast radius)",
        "graph/dependency_reach.py `_REACH_EDGE_TYPES` + `_VULN_TO_PACKAGE_EDGE_TYPES`",
        frozenset(r.value for r in dependency_reach._REACH_EDGE_TYPES | dependency_reach._VULN_TO_PACKAGE_EDGE_TYPES),
    ),
    (
        "LT",
        "Toxic-combination lateral reach",
        "graph/toxic_findings.py `_LATERAL_RELS`",
        frozenset(r.value for r in toxic_findings._LATERAL_RELS),
    ),
    (
        "MT",
        "ATT&CK / ATLAS hop mapping",
        "graph/attack_path_mitre.py `_DATA_ACCESS_RELS`, `_VULN_RELS`, `_CRED_RELS`, `_TOOL_RELS`, `_ASSUME_RELS`",
        frozenset(
            r.value
            for r in attack_path_mitre._DATA_ACCESS_RELS
            | attack_path_mitre._VULN_RELS
            | attack_path_mitre._CRED_RELS
            | attack_path_mitre._TOOL_RELS
            | attack_path_mitre._ASSUME_RELS
        ),
    ),
    (
        "RT",
        "Runtime-observed path evidence",
        "graph/path_derivation.py `_RUNTIME_OBSERVED_RELS`",
        frozenset(path_derivation._RUNTIME_OBSERVED_RELS),
    ),
)

TIER_MEANING = {
    "modeled_infrastructure": "Configuration read from a provider or inventory API.",
    "static_scan": "A scanner read files, manifests or source.",
    "static_evidence": "Static evidence supplied with the input (contract tier; no registered collector uses it).",
    "recorded": "Logs, audit trails, usage history or attestations recorded the activity.",
    "runtime_observed": "The runtime proxy, gateway or feedback loop observed it live.",
    "derived": "Computed from other edges; must name `derived_via`.",
    LEGACY_TIER: "Read-side label for edges stored before the evidence envelope existed; never written.",
}

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
        "graph_schema.py",
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


def _module_key(path: Path) -> str:
    return path.relative_to(PKG_DIR).as_posix()


def _is_demo(module: str) -> bool:
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
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if in_graph and node.value in finding_values:
                    result.finding_refs[node.value].add(module)
            if in_graph and isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in finding_alias and node.attr in finding_members:
                    result.finding_refs[FindingType[node.attr].value].add(module)
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name == "edge_evidence" and len(node.args) >= 2 and isinstance(node.args[0], ast.Constant):
                tier_node = node.args[1]
                tier = tier_node.value if isinstance(tier_node, ast.Constant) else consts.get(getattr(tier_node, "id", ""), "")
                if isinstance(node.args[0].value, str) and tier:
                    result.collector_tiers[node.args[0].value].add(str(tier))
            if name == "UnifiedNode":
                kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
                member = _enum_member(kwargs.get("entity_type", ast.Constant(None)), ent_alias, entity_members)
                id_node = kwargs.get("id")
                if isinstance(id_node, ast.Name):
                    templates = _resolve_id_name(node, id_node.id, parents, named_ids)
                else:
                    templates = {t for t in [_template(id_node)] if t} if id_node is not None else set()
                if member:
                    result.node_id_formats[EntityType[member].value].update(templates)
    return result


def _code(value: str) -> str:
    return f"`{value}`"


def _codes(values: Iterable[str]) -> str:
    return ", ".join(_code(v) for v in values) or "—"


def _cap(values: list[str], limit: int) -> str:
    shown = ", ".join(values[:limit])
    return shown + (f" (+{len(values) - limit} more)" if len(values) > limit else "") if values else "—"


def _legend() -> dict[str, tuple[str, str]]:
    return {entry.key: (entry.label, entry.layer) for entry in ENTITY_LEGEND}


def _domain_of() -> dict[str, str]:
    layer_domain = {layer.value: key for key, _label, layers in DOMAINS for layer in layers}
    legend = _legend()
    mapping: dict[str, str] = {}
    for entity in EntityType:
        if entity.value not in legend:
            raise SystemExit(f"entity type {entity.value!r} has no ENTITY_LEGEND entry")
        layer = legend[entity.value][1]
        if layer not in layer_domain:
            raise SystemExit(f"semantic layer {layer!r} has no diagram domain in {GENERATOR}")
        mapping[entity.value] = layer_domain[layer]
    return mapping


def _specs() -> list[RelationshipSpec]:
    missing = [r.value for r in RelationshipType if r not in RELATIONSHIP_SPECS]
    if missing:
        raise SystemExit(f"relationship types without a RelationshipSpec: {missing}")
    return [RELATIONSHIP_SPECS[r] for r in sorted(RelationshipType, key=lambda r: r.value)]


def _consumers(rel: str) -> list[str]:
    return [code for code, _name, _where, rels in ANALYSES if rel in rels]


def _emitters(scan: ScanResult, rel_or_entity: str, *, rel: bool) -> tuple[list[str], list[str]]:
    modules = sorted((scan.rel_emitters if rel else scan.entity_emitters).get(rel_or_entity, set()))
    return [m for m in modules if not _is_demo(m)], [m for m in modules if _is_demo(m)]


def _mermaid() -> list[str]:
    domain_of = _domain_of()
    edges: dict[tuple[str, str], set[str]] = defaultdict(set)
    for spec in _specs():
        for source, target in spec.allowed_pairs:
            edges[(domain_of[source.value], domain_of[target.value])].add(spec.rel.value)
    lines = ["```mermaid", "flowchart LR"]
    for key, label, _layers in DOMAINS:
        members = sorted(e.value for e in EntityType if domain_of[e.value] == key)
        lines.append(f'  subgraph {key}["{label}"]')
        lines.extend(f"    {key}_{i}[{' · '.join(members[i : i + 4])}]" for i in range(0, len(members), 4))
        lines.append("  end")
    for (src, dst), rels in sorted(edges.items()):
        label = "<br/>".join(", ".join(chunk) for chunk in _chunks(sorted(rels), 4))
        lines.append(f'  {src} -- "{label}" --> {dst}')
    lines.append("```")
    return lines


def _chunks(values: list[str], size: int) -> list[list[str]]:
    return [values[i : i + size] for i in range(0, len(values), size)]


def _find_trace_event_type() -> type | None:
    """``NormalizedTraceEvent`` from ``agent_bom.runtime``, when that type exists."""
    pattern = re.compile(r"^class NormalizedTraceEvent\b", re.MULTILINE)
    for path in sorted((PKG_DIR / "runtime").rglob("*.py")):
        if pattern.search(path.read_text(encoding="utf-8")):
            dotted = ".".join(path.relative_to(SRC_ROOT).with_suffix("").parts)
            return getattr(importlib.import_module(dotted), "NormalizedTraceEvent", None)
    return None


def _type_text(annotation: Any) -> str:
    if isinstance(annotation, str):
        return annotation
    text = getattr(annotation, "__name__", None) if isinstance(annotation, type) else None
    return text or str(annotation).replace("typing.", "")


def _trace_event_lines(event_type: type | None) -> list[str]:
    if event_type is None:
        return []
    lines = ["<!-- trace-event-schema:start -->", "## Normalized trace event", ""]
    doc = inspect.getdoc(event_type) or ""
    if doc:
        lines += [doc.splitlines()[0], ""]
    lines += [f"Source: `{event_type.__module__}.{event_type.__qualname__}`.", "", "| Field | Type | Description |", "|---|---|---|"]
    rows: list[tuple[str, str, str]] = []
    model_fields = getattr(event_type, "model_fields", None)
    if isinstance(model_fields, dict):
        rows = [(name, _type_text(f.annotation), f.description or "") for name, f in model_fields.items()]
    elif dataclasses.is_dataclass(event_type):
        rows = [(f.name, _type_text(f.type), str(f.metadata.get("description", ""))) for f in dataclasses.fields(event_type)]
    lines += [f"| {_code(n)} | {_code(t)} | {d} |" for n, t, d in rows]
    return [*lines, "", "<!-- trace-event-schema:end -->", ""]


def _header(title: str, intro: str) -> list[str]:
    return [
        f"# {title}",
        "",
        f"> Generated from the code by `{GENERATOR}`. Do not edit by hand: re-run the",
        "> generator and commit the result. CI runs it with `--check` and fails on drift.",
        "",
        intro,
        "",
    ]


def _render_main(scan: ScanResult) -> list[str]:
    legend = _legend()
    domain_label = {key: label for key, label, _ in DOMAINS}
    domain_of = _domain_of()
    specs = _specs()
    out = _header(
        "Security graph data model",
        "Every node kind, edge kind, evidence tier and normalization table behind the security graph. "
        "The [graph contract](CONTRACT.md) states what the graph guarantees; this page lists what it is made of. "
        "Detail pages: [relationship pairs](data-model/relationships.md) · [entity emitters and id formats](data-model/entities.md).",
    )
    out += [
        "## Overview",
        "",
        "Entity types grouped by domain (from each type's semantic layer in `graph/container.py` `ENTITY_LEGEND`). "
        "An arrow carries every relationship whose allowed pairs connect the two domains.",
        "",
        *_mermaid(),
        "",
        "## Entities",
        "",
        f"{len(EntityType)} entity types (`agent_bom.core.entity_types.EntityType`). "
        "Emitting modules are found by a static scan for call sites that pass the literal enum member; "
        "see [entities](data-model/entities.md) for the module list and node id formats.",
        "",
        "| Entity | Label | Domain | Semantic layer | OCSF category / class | Finding | Emitting modules |",
        "|---|---|---|---|---|---|---|",
    ]
    for entity in sorted(EntityType, key=lambda e: e.value):
        label, layer = legend[entity.value]
        ocsf = ENTITY_OCSF_MAP.get(entity, {})
        prod, demo = _emitters(scan, entity.value, rel=False)
        emitted = f"{len(prod)}" + (f" (+{len(demo)} demo)" if demo else "")
        finding = "yes" if entity in FINDING_ENTITY_TYPES else ""
        out.append(
            f"| {_code(entity.value)} | {label} | {domain_label[domain_of[entity.value]]} | {_code(layer)} | "
            f"{ocsf.get('category_uid', 0)} / {ocsf.get('class_uid', 0)} | {finding} | {emitted} |"
        )
    analysis_key = " · ".join(f"**{code}** {name}" for code, name, _w, _r in ANALYSES)
    out += [
        "",
        "## Relationships",
        "",
        f"{len(specs)} relationship types, one `RelationshipSpec` each (`agent_bom.graph.relationship_specs`). "
        "Source and target kinds are the spec's `source_types` / `target_types`; "
        "the exact allowed pairs are in [relationship pairs](data-model/relationships.md). "
        "*Traversable* is the default for the attack-path view "
        "(`UnifiedGraph.attack_path_view` keeps traversable edges only).",
        "",
        f"Consumed by: {analysis_key}.",
        "",
        "| Relationship | Class | Category | Direction | Traversable | Source kinds | Target kinds | Pairs | Consumed by "
        "| Emitting modules |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for spec in specs:
        prod, demo = _emitters(scan, spec.rel.value, rel=True)
        emitted = f"{len(prod)}" + (f" (+{len(demo)} demo)" if demo else "")
        sources = sorted(s.value for s in spec.source_types)
        targets = sorted(t.value for t in spec.target_types)
        out.append(
            f"| {_code(spec.rel.value)} | {_code(spec.traversal_class.value)} | {spec.category} | {spec.direction} | "
            f"{'yes' if spec.default_traversable else 'no'} | {_cap([_code(s) for s in sources], 6)} | "
            f"{_cap([_code(t) for t in targets], 6)} | {len(spec.allowed_pairs)} | "
            f"{', '.join(_consumers(spec.rel.value)) or '—'} | {emitted} |"
        )
    out += ["", "### Traversal classes", "", "| Class | Relationships |", "|---|---|"]
    for traversal in TraversalClass:
        members = sorted(s.rel.value for s in specs if s.traversal_class == traversal)
        out.append(f"| {_code(traversal.value)} | {_codes(members)} |")
    out += ["", "### Analysis edge sets", "", "| Code | Analysis | Defined in | Relationships |", "|---|---|---|---|"]
    for code, name, where, edge_set in ANALYSES:
        out.append(f"| {code} | {name} | {where} | {_codes(sorted(edge_set))} |")
    out += _render_evidence(scan)
    out += _render_findings(scan)
    out += _render_normalization()
    out += _trace_event_lines(_find_trace_event_type())
    out += _render_coverage_notes(scan)
    return out


def _render_evidence(scan: ScanResult) -> list[str]:
    out = [
        "",
        "## Edge evidence tiers",
        "",
        "Every edge carries `evidence.source` (the collector) and `evidence.tier` (`agent_bom.graph.edge_evidence`). "
        "A collector in the registry below gets its tier filled automatically; any other collector must set it explicitly.",
        "",
        "| Tier | Meaning | Registered collectors |",
        "|---|---|---|",
    ]
    by_tier: dict[str, list[str]] = defaultdict(list)
    for source, tier in SOURCE_TIERS.items():
        by_tier[tier].append(source)
    for tier in sorted(EDGE_EVIDENCE_TIERS):
        out.append(f"| {_code(tier)} | {TIER_MEANING.get(tier, '')} | {_codes(sorted(by_tier.get(tier, [])))} |")
    explicit = {c: t for c, t in scan.collector_tiers.items() if c not in SOURCE_TIERS}
    if explicit:
        out += ["", "Collectors that set their tier at the call site (`edge_evidence(source, tier)`), outside the registry:", ""]
        out += ["| Collector | Tier(s) |", "|---|---|"]
        out += [f"| {_code(c)} | {_codes(sorted(t))} |" for c, t in sorted(explicit.items())]
    return out


def _render_findings(scan: ScanResult) -> list[str]:
    out = [
        "",
        "## Findings",
        "",
        "Findings (`agent_bom.finding.Finding`) are linked to graph nodes by `graph/asset_entity.py` "
        "`link_findings_to_graph_nodes`: the finding node is a `vulnerability`, `misconfiguration` or `drift_incident` node; "
        "the affected asset resolves through the asset-type table below. "
        "*Graph modules* lists modules under `graph/` that name the finding type (enum member or literal value).",
        "",
        "| Finding type | Graph modules |",
        "|---|---|",
    ]
    for ftype in sorted(FindingType, key=lambda f: f.value):
        out.append(f"| {_code(ftype.value)} | {_cap([_code(m) for m in sorted(scan.finding_refs.get(ftype.value, set()))], 4)} |")
    out += [
        "",
        "| Finding source | Registered edge collector (name match) | Tier |",
        "|---|---|---|",
    ]
    for source in sorted(FindingSource, key=lambda f: f.value):
        collector = next((c for c in (source.value.lower().replace("_", "-"), source.value.lower()) if c in SOURCE_TIERS), "")
        tier = SOURCE_TIERS.get(collector, "")
        out.append(f"| {_code(source.value)} | {_code(collector) if collector else '—'} | {_code(tier) if tier else '—'} |")
    out += ["", "Finding node id formats (statically detected `UnifiedNode(id=…)` call sites):", "", "| Entity | Id format |", "|---|---|"]
    for entity in sorted(FINDING_ENTITY_TYPES, key=lambda e: e.value):
        for template in sorted(scan.node_id_formats.get(entity.value, set())):
            out.append(f"| {_code(entity.value)} | {_code(template)} |")
    return out


def _render_normalization() -> list[str]:
    out = [
        "",
        "## Asset-type normalization",
        "",
        "`agent_bom.core.asset_types.entity_type_for_asset_type` lowercases the vendor or scanner `asset_type`, "
        "turns `-` and spaces into `_`, then maps it. Every entity type value maps to itself; "
        "the aliases below map other spellings. Unknown values stay unmapped rather than guessed.",
        "",
        "| Asset type | Entity |",
        "|---|---|",
    ]
    aliases = sorted((k, v.value) for k, v in _ASSET_TYPE_ALIASES.items() if k != v.value)
    out += [f"| {_code(k)} | {_code(v)} |" for k, v in aliases]
    out += ["", "## Canonical identifiers", "", "Stable ids come from `agent_bom.canonical_ids` (UUIDv5 over normalized parts).", ""]
    out += ["| Function | Signature |", "|---|---|"]
    for name, func in sorted(inspect.getmembers(canonical_ids, inspect.isfunction)):
        if name.startswith("canonical_") and func.__module__ == canonical_ids.__name__:
            out.append(f"| {_code(name)} | {_code(str(inspect.signature(func)))} |")
    return out


def _render_coverage_notes(scan: ScanResult) -> list[str]:
    no_rel = [r.value for r in sorted(RelationshipType, key=lambda r: r.value) if not _emitters(scan, r.value, rel=True)[0]]
    no_ent = [e.value for e in sorted(EntityType, key=lambda e: e.value) if not _emitters(scan, e.value, rel=False)[0]]
    unused = sorted(c for c in SOURCE_TIERS if c not in scan.referenced_collectors)
    no_collector = sorted(
        s.value for s in FindingSource if not any(c in SOURCE_TIERS for c in (s.value.lower().replace("_", "-"), s.value.lower()))
    )
    return [
        "",
        "## Coverage notes",
        "",
        "Static-scan results. A kind can still be emitted through a table or a variable the scan cannot see; "
        "treat these as leads to verify, not as defects.",
        "",
        f"- Relationship types with no detected non-demo emitter: {_codes(no_rel)}",
        f"- Entity types with no detected non-demo emitter: {_codes(no_ent)}",
        f"- Registered collectors never named elsewhere in the source: {_codes(unused)}",
        f"- Finding sources without a same-named registered collector: {_codes(no_collector)}",
        "",
    ]


def _render_relationships(scan: ScanResult) -> list[str]:
    out = _header(
        "Relationship pairs",
        "Allowed source → target pairs for every relationship type (`RelationshipSpec.allowed_pairs`), "
        "and the modules found emitting it. Back to the [data model](../DATA_MODEL.md).",
    )
    for spec in _specs():
        prod, demo = _emitters(scan, spec.rel.value, rel=True)
        out += [
            f"## `{spec.rel.value}`",
            "",
            f"Class {_code(spec.traversal_class.value)} · {spec.direction} · "
            f"{'traversable' if spec.default_traversable else 'not traversable'} · "
            f"required evidence {_codes(spec.required_evidence)} · {len(spec.allowed_pairs)} pairs",
            "",
        ]
        targets_by_source: dict[str, list[str]] = defaultdict(list)
        for source, target in spec.allowed_pairs:
            targets_by_source[source.value].append(target.value)
        out += [f"- {_code(s)} → {_codes(sorted(t))}" for s, t in sorted(targets_by_source.items())]
        out += ["", f"Emitted by: {_codes(prod)}" + (f"; demo fixtures: {_codes(demo)}" if demo else ""), ""]
    return out


def _render_entities(scan: ScanResult) -> list[str]:
    out = _header(
        "Entity emitters and id formats",
        "Modules found emitting each entity type, and node id formats from `UnifiedNode(id=…)` call sites "
        "that pass a literal entity type. Back to the [data model](../DATA_MODEL.md).",
    )
    for entity in sorted(EntityType, key=lambda e: e.value):
        prod, demo = _emitters(scan, entity.value, rel=False)
        out += [f"## `{entity.value}`", "", f"Emitted by: {_codes(prod)}" + (f"; demo fixtures: {_codes(demo)}" if demo else "")]
        formats = sorted(scan.node_id_formats.get(entity.value, set()))
        if formats:
            out += ["", "Id formats:", "", *(f"- {_code(f)}" for f in formats)]
        out.append("")
    return out


def render() -> dict[str, str]:
    scan = scan_source()
    docs = {
        MAIN_DOC: _render_main(scan),
        REL_DOC: _render_relationships(scan),
        ENTITY_DOC: _render_entities(scan),
    }
    rendered: dict[str, str] = {}
    for path, lines in docs.items():
        text = "\n".join(lines).rstrip("\n") + "\n"
        if len(text.splitlines()) > LINE_CEILING:
            raise SystemExit(f"{path} would exceed {LINE_CEILING} lines; split it further")
        rendered[path] = text
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--check", action="store_true", help="fail when a committed doc differs from the generated output")
    args = parser.parse_args(argv)
    rendered = render()
    if args.check:
        stale = [p for p, text in rendered.items() if not (ROOT / p).is_file() or (ROOT / p).read_text(encoding="utf-8") != text]
        if stale:
            print("Graph data-model docs are stale. Regenerate with:", file=sys.stderr)
            print(f"  python {GENERATOR}", file=sys.stderr)
            for path in stale:
                print(f"  stale: {path}", file=sys.stderr)
            return 1
        print(f"Graph data-model docs are current ({len(rendered)} files).")
        return 0
    for path, text in rendered.items():
        target = ROOT / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(f"wrote {path} ({len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
