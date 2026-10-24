"""Fixed-layout SVG of the security graph data model, in dark and light.

Auto-laid-out diagrams of every allowed relationship are unreadable at this
size, so this draws two things on a fixed grid: the domains with their entity
types, and the backbone path a reader follows from an agent to what it can
reach. Every drawn relationship is checked against the relationship specs.
"""

from __future__ import annotations

from collections.abc import Sequence

from agent_bom.graph.relationship_specs import RelationshipSpec

PATHS = {theme: f"docs/images/graph-data-model-{theme}.svg" for theme in ("dark", "light")}
FONT = "Inter,system-ui,-apple-system,Segoe UI,sans-serif"

PALETTE = {
    "dark": {
        "bg": "#0a0a0c",
        "card": "#111114",
        "card_stroke": "#26262c",
        "title": "#f4f4f5",
        "text": "#e4e4e7",
        "muted": "#8b8b95",
        "arrow": "#71717a",
        "ai": ("#a78bfa", "#1b1630"),
        "supply": ("#60a5fa", "#111c2e"),
        "findings": ("#f87171", "#2a1416"),
        "cloud": ("#fbbf24", "#2a2110"),
        "identity": ("#34d399", "#0f241c"),
    },
    "light": {
        "bg": "#ffffff",
        "card": "#fafafa",
        "card_stroke": "#e4e4e7",
        "title": "#18181b",
        "text": "#27272a",
        "muted": "#71717a",
        "arrow": "#a1a1aa",
        "ai": ("#6d28d9", "#f3efff"),
        "supply": ("#1d4ed8", "#eef4ff"),
        "findings": ("#b91c1c", "#fdf0f0"),
        "cloud": ("#b45309", "#fdf6e7"),
        "identity": ("#047857", "#ecfaf3"),
    },
}

# The path a reader follows, row by row: (source, relationship, target).
BACKBONE: tuple[tuple[tuple[str, str, str], ...], ...] = (
    (("agent", "uses", "server"), ("server", "depends_on", "package"), ("package", "vulnerable_to", "vulnerability")),
    (("server", "exposes_cred", "credential"),),
    (("server", "provides_tool", "tool"), ("tool", "can_access", "data_store")),
    (("cloud_resource", "assumes", "role"), ("role", "can_access", "data_store")),
)

WIDTH = 1480
MARGIN = 32
GAP = 18
CHIP_H = 24
CHIP_GAP = 6


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _text(x: float, y: float, content: str, size: float, fill: str, weight: int = 500, anchor: str = "start") -> str:
    return (
        f'<text x="{x:.0f}" y="{y:.0f}" font-family="{FONT}" font-size="{size}" font-weight="{weight}" '
        f'fill="{fill}" text-anchor="{anchor}">{_esc(content)}</text>'
    )


def _chip(x: float, y: float, w: float, label: str, colors: tuple[str, str], t: dict) -> str:
    accent, fill = colors
    return (
        f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{CHIP_H}" rx="6" fill="{fill}" stroke="{accent}" '
        f'stroke-opacity="0.55"/>' + _text(x + w / 2, y + 16, label, 11.5, t["text"], 600, "middle")
    )


def _check_backbone(specs: list[RelationshipSpec]) -> None:
    allowed = {(a.value, s.rel.value, b.value) for s in specs for a, b in s.allowed_pairs}
    missing = [step for row in BACKBONE for step in row if step not in allowed]
    if missing:
        raise SystemExit(f"data-model diagram draws relationships the specs do not allow: {missing}")


def _domains_row(t: dict, ordered: Sequence[tuple[str, str]], members: dict[str, list[str]], top: int) -> tuple[list[str], int]:
    col_w = (WIDTH - 2 * MARGIN - GAP * (len(ordered) - 1)) / len(ordered)
    rows = max((len(members[key]) + 1) // 2 for key, _ in ordered)
    card_h = 58 + rows * (CHIP_H + CHIP_GAP) + 8
    out: list[str] = []
    for i, (key, label) in enumerate(ordered):
        x = MARGIN + i * (col_w + GAP)
        accent, _fill = t[key]
        out.append(
            f'<rect x="{x:.0f}" y="{top}" width="{col_w:.0f}" height="{card_h}" rx="10" fill="{t["card"]}" stroke="{t["card_stroke"]}"/>'
        )
        out.append(f'<rect x="{x:.0f}" y="{top}" width="{col_w:.0f}" height="4" rx="2" fill="{accent}"/>')
        out.append(_text(x + 14, top + 26, label, 13.5, t["title"], 700))
        out.append(_text(x + 14, top + 43, f"{len(members[key])} entity types", 11, t["muted"], 500))
        chip_w = (col_w - 14 * 2 - 8) / 2
        for j, name in enumerate(members[key]):
            cx = x + 14 + (j % 2) * (chip_w + 8)
            cy = top + 56 + (j // 2) * (CHIP_H + CHIP_GAP)
            out.append(_chip(cx, cy, chip_w, name, t[key], t))
        if i < len(ordered) - 1:
            ax = x + col_w + GAP / 2
            ay = top + card_h / 2
            out.append(
                f'<path d="M{ax - 4:.0f} {ay - 6:.0f} L{ax + 3:.0f} {ay:.0f} L{ax - 4:.0f} {ay + 6:.0f}" '
                f'stroke="{t["arrow"]}" stroke-width="1.6" fill="none" stroke-linecap="round"/>'
            )
    return out, top + card_h


def _arrow(x1: float, x2: float, y: float, label: str, t: dict) -> list[str]:
    return [
        f'<line x1="{x1:.0f}" y1="{y:.0f}" x2="{x2 - 6:.0f}" y2="{y:.0f}" stroke="{t["arrow"]}" stroke-width="1.6"/>',
        f'<path d="M{x2 - 8:.0f} {y - 5:.0f} L{x2:.0f} {y:.0f} L{x2 - 8:.0f} {y + 5:.0f}" fill="{t["arrow"]}"/>',
        _text((x1 + x2) / 2, y - 7, label, 11, t["muted"], 600, "middle"),
    ]


def _backbone(t: dict, domain_of: dict[str, str], top: int) -> tuple[list[str], int]:
    chip_w, step = 150.0, 260.0
    out = [
        _text(MARGIN, top, "How a path reads", 15, t["title"], 700),
        _text(
            MARGIN,
            top + 20,
            "Backbone relationships from an agent to what it can reach. Every other relationship is listed by name on the domain pages.",
            12,
            t["muted"],
        ),
    ]
    y0 = top + 46
    placed: dict[str, tuple[float, float, int]] = {}
    for row_index, row in enumerate(BACKBONE):
        y = y0 + row_index * 46
        mid = y + CHIP_H / 2
        start = row[0][0]
        if start in placed:
            # A branch off a chip already drawn: run a right-angled connector
            # down from it instead of drawing the same entity again.
            px, py, col = placed[start]
            sx = px + chip_w / 2
            out.append(f'<path d="M{sx:.0f} {py + CHIP_H:.0f} V{mid:.0f}" stroke="{t["arrow"]}" stroke-width="1.6" fill="none"/>')
            origin = sx
        else:
            col = 0
            out.append(_chip(MARGIN, y, chip_w, start, t[domain_of[start]], t))
            placed[start] = (MARGIN, y, col)
            origin = MARGIN + chip_w
        for source, rel, target in row:
            col = placed[source][2] + 1
            xt = MARGIN + col * step
            out += _arrow(origin, xt, mid, rel, t)
            out.append(_chip(xt, y, chip_w, target, t[domain_of[target]], t))
            placed.setdefault(target, (xt, y, col))
            if target not in placed or placed[target][1] != y:
                placed[target] = placed.get(target, (xt, y, col))
            origin = xt + chip_w
    return out, y0 + len(BACKBONE) * 46


def render(
    ordered: Sequence[tuple[str, str]],
    members: dict[str, list[str]],
    domain_of: dict[str, str],
    specs: list[RelationshipSpec],
) -> dict[str, list[str]]:
    _check_backbone(specs)
    docs: dict[str, list[str]] = {}
    for theme, path in PATHS.items():
        t = PALETTE[theme]
        body = [
            _text(MARGIN, 40, "Security graph data model", 20, t["title"], 700),
            _text(
                MARGIN,
                62,
                "Entity types by domain, in the order an exposure path crosses them. Generated from the code.",
                12.5,
                t["muted"],
            ),
        ]
        cards, bottom = _domains_row(t, ordered, members, 84)
        path_svg, end = _backbone(t, domain_of, bottom + 44)
        height = end + 24
        docs[path] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" viewBox="0 0 {WIDTH} {height}" fill="none">',
            "<title>Security graph data model</title>",
            f'<rect width="{WIDTH}" height="{height}" fill="{t["bg"]}"/>',
            *body,
            *cards,
            *path_svg,
            "</svg>",
        ]
    return docs
