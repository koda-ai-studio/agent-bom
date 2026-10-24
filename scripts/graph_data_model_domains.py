"""Domain overview and per-domain ERD pages for the security graph data model.

The overview shows only the domains and how many relationships connect each
pair, so it stays readable. Each domain page draws an ERD of its own entity
types and lists every relationship that leaves or enters the domain.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence

from agent_bom.core.entity_types import EntityType
from agent_bom.graph.relationship_specs import RelationshipSpec

DOMAIN_DIR = "docs/graph/data-model/domains"
# Left to right along an attack path: the agents and what they run, the
# software they pull in, what is wrong with it, what it can reach, and the
# identities it acts as.
CHAIN = ("ai", "supply", "findings", "cloud", "identity")
LABEL_CAP = 3
# Overlays connect almost any two types (a trace hop, a candidate identity
# match), so drawing them would hide the domain's structure. They are named
# under each diagram instead.
OVERLAY_RELATIONSHIPS = frozenset({"trace_step"})
OVERLAY_CLASSES = frozenset({"correlation", "derived"})
# One view per kind of relationship. A view with more lines than this becomes a
# source-by-target matrix: past that density a diagram is unreadable.
VIEWS = (
    ("Structure", "what contains, depends on or governs what", frozenset({"structural", "dependency", "governance"})),
    ("Exposure and runtime", "what is exposed to, observed or affected", frozenset({"exposure", "runtime", "finding"})),
    ("Authority", "who can act on what", frozenset({"authority"})),
)
MAX_DRAWN_LINES = 15

Domains = Sequence[tuple[str, str, Iterable[object]]]
Pair = tuple[str, str, str, RelationshipSpec]


def ordered(domains: Domains) -> list[tuple[str, str]]:
    labels = {key: label for key, label, _layers in domains}
    missing = set(labels) - set(CHAIN)
    if missing:
        raise SystemExit(f"domains {sorted(missing)} have no place in the overview chain")
    return [(key, labels[key]) for key in CHAIN if key in labels]


def _pairs(specs: list[RelationshipSpec], domain_of: dict[str, str]) -> list[Pair]:
    rows = {(source.value, spec.rel.value, target.value): spec for spec in specs for source, target in spec.allowed_pairs}
    return sorted(
        ((src, rel, dst, spec) for (src, rel, dst), spec in rows.items()),
        key=lambda row: (CHAIN.index(domain_of[row[0]]), row[0], row[1], row[2]),
    )


def _is_overlay(spec: RelationshipSpec) -> bool:
    return spec.rel.value in OVERLAY_RELATIONSHIPS or spec.traversal_class.value in OVERLAY_CLASSES


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _wrap(label: str, width: int = 18) -> str:
    """Break a long box label at the space nearest its middle so Mermaid never clips it."""
    if len(label) <= width or " " not in label:
        return label
    spaces = [i for i, c in enumerate(label) if c == " "]
    cut = min(spaces, key=lambda i: abs(i - len(label) / 2))
    return f"{label[:cut]}<br/>{label[cut + 1 :]}"


def _members(key: str, domain_of: dict[str, str]) -> list[str]:
    return sorted(e.value for e in EntityType if domain_of[e.value] == key)


def _capped(values: list[str]) -> str:
    shown = ", ".join(values[:LABEL_CAP])
    return shown + (f" +{len(values) - LABEL_CAP}" if len(values) > LABEL_CAP else "")


def _types(values: set[str], key: str, domain_of: dict[str, str], labels: dict[str, str]) -> str:
    own = sorted(v for v in values if domain_of[v] == key)
    other: dict[str, list[str]] = defaultdict(list)
    for value in sorted(values):
        if domain_of[value] != key:
            other[labels[domain_of[value]]].append(value)
    parts = [", ".join(f"`{v}`" for v in own)] if own else []
    parts += [f"{label}: " + ", ".join(f"`{v}`" for v in names) for label, names in other.items()]
    return "<br/>".join(parts)


def _view(rows: list[Pair]) -> list[str]:
    joined: dict[tuple[str, str], set[str]] = defaultdict(set)
    for src, rel, dst, _spec in rows:
        joined[(src, dst)].add(rel)
    undirected: dict[tuple[str, str], set[str]] = defaultdict(set)
    for (src, dst), rels in joined.items():
        undirected[tuple(sorted((src, dst)))] |= rels  # type: ignore[index]
    if len(undirected) <= MAX_DRAWN_LINES:
        lines = ["```mermaid", "erDiagram"]
        lines += [f'  {a} }}o--o{{ {b} : "{_capped(sorted(rels))}"' for (a, b), rels in sorted(undirected.items())]
        return lines + ["```"]
    sources = sorted({src for src, _dst in joined})
    targets = sorted({dst for _src, dst in joined})
    lines = [
        f"{len(undirected)} type pairs, too many to draw legibly. Read a row as *source → relationship → target*.",
        "",
        "| Source ↓ / target → | " + " | ".join(f"`{t}`" for t in targets) + " |",
        "|---" * (len(targets) + 1) + "|",
    ]
    for src in sources:
        cells = ["<br/>".join(sorted(joined.get((src, dst), set()))) for dst in targets]
        lines.append(f"| `{src}` | " + " | ".join(cells) + " |")
    return lines


def members_by_domain(domain_of: dict[str, str]) -> dict[str, list[str]]:
    return {key: _members(key, domain_of) for key in CHAIN}


def page_path(key: str) -> str:
    return f"{DOMAIN_DIR}/{key}.md"


def overview(domains: Domains, specs: list[RelationshipSpec], domain_of: dict[str, str], link_prefix: str) -> list[str]:
    chain = ordered(domains)
    internal: dict[str, set[str]] = defaultdict(set)
    crossing: dict[str, set[str]] = defaultdict(set)
    for src, rel, dst, _spec in _pairs(specs, domain_of):
        a, b = domain_of[src], domain_of[dst]
        if a == b:
            internal[a].add(rel)
        else:
            crossing[a].add(rel)
            crossing[b].add(rel)
    lines = [
        '<p align="center"><picture><source media="(prefers-color-scheme: light)" '
        'srcset="../images/graph-data-model-light.svg"><img src="../images/graph-data-model-dark.svg" '
        'alt="Security graph domains with their entity types, and the backbone path from an agent through its '
        'MCP server, packages and vulnerabilities to credentials, tools and data stores" width="100%"></picture></p>',
    ]
    lines += ["", "| Domain | Entity types | Relationships inside | To other domains | Detail |", "|---|---|---|---|---|"]
    for key, label in chain:
        members = ", ".join(f"`{m}`" for m in _members(key, domain_of))
        lines.append(
            f"| {label} | {members} | {len(internal[key])} | {len(crossing[key])} | [ERD and relationships]({link_prefix}{key}.md) |"
        )
    return lines


def render(
    domains: Domains,
    specs: list[RelationshipSpec],
    domain_of: dict[str, str],
    header: Callable[[str, str], list[str]],
) -> dict[str, list[str]]:
    labels = dict(ordered(domains))
    pairs = _pairs(specs, domain_of)
    pages: dict[str, list[str]] = {}
    for key, label in labels.items():
        inside = [p for p in pairs if domain_of[p[0]] == key and domain_of[p[2]] == key]
        crossing = [p for p in pairs if (domain_of[p[0]] == key) != (domain_of[p[2]] == key)]
        out = header(
            f"{label}: entity relationships",
            f"Entity types in the {label.lower()} domain and the relationships allowed between them. "
            "A line means the relationship is allowed between the two types; cardinality is not modelled. "
            "Back to the [data model](../../DATA_MODEL.md) · [all relationship pairs](../relationships.md).",
        )
        overlays = sorted({p[1] for p in inside + crossing if _is_overlay(p[3])})
        out += ["## Inside the domain", ""]
        drawn_any = False
        for view, meaning, classes in VIEWS:
            rows = [p for p in inside if not _is_overlay(p[3]) and p[3].traversal_class.value in classes]
            if rows:
                out += [f"### {view}: {meaning}", "", *_view(rows), ""]
                drawn_any = True
        if not drawn_any:
            out += ["No relationship connects two types inside this domain.", ""]
        if overlays:
            out += [
                "Not drawn, because they can connect almost any two types: "
                + ", ".join(f"`{rel}`" for rel in overlays)
                + ". They are listed in the tables below.",
                "",
            ]
        out += ["## Relationship reference", ""]
        for title, rows in (("Inside the domain", inside), ("Across domains", crossing)):
            grouped: dict[str, tuple[RelationshipSpec, set[str], set[str]]] = {}
            for src, rel, dst, spec in rows:
                entry = grouped.setdefault(rel, (spec, set(), set()))
                entry[1].add(src)
                entry[2].add(dst)
            out += [f"### {title}", "", "| Relationship | Class | Traversable | From | To |", "|---|---|---|---|---|"]
            for rel, (spec, sources, targets) in sorted(grouped.items()):
                out.append(
                    f"| `{rel}` | `{spec.traversal_class.value}` | {'yes' if spec.default_traversable else 'no'} | "
                    f"{_types(sources, key, domain_of, labels)} | {_types(targets, key, domain_of, labels)} |"
                )
            out.append("")
        pages[page_path(key)] = out
    return pages
