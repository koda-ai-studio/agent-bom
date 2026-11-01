"""Dependency edges of a ``package-lock.json`` tree.

Reconstructs which dependency introduced each installed package the way node
resolves it, so a lockfile finding can say "qs is vulnerable because express
depends on it" rather than only "qs is vulnerable".
"""

from __future__ import annotations

_DEPENDENCY_SECTION_SCOPES: tuple[tuple[str, str], ...] = (
    ("dependencies", "runtime"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
    ("devDependencies", "dev"),
)


def _npm_lock_entry_name(lock_path: str) -> str:
    """Package name for a lockfile install path.

    ``node_modules/b/node_modules/shared`` installs *shared*, not
    ``b/shared`` — a blanket ``replace("node_modules/", "")`` mangled every
    nested (version-conflicting) install into a name no advisory feed knows.
    """
    marker = "node_modules/"
    idx = lock_path.rfind(marker)
    if idx >= 0:
        return lock_path[idx + len(marker) :]
    return lock_path.lstrip("/")


def _npm_resolve_install_path(entries: dict, from_path: str, dep_name: str) -> str | None:
    """Resolve ``dep_name`` from ``from_path`` the way node does.

    Node walks up the enclosing ``node_modules`` directories and takes the first
    copy it finds, so a nested install shadows the hoisted one for its own
    subtree. Reproducing that is what makes the introducing path correct rather
    than merely plausible.
    """
    prefix = from_path
    while True:
        candidate = f"{prefix}/node_modules/{dep_name}" if prefix else f"node_modules/{dep_name}"
        if candidate in entries:
            return candidate
        if not prefix:
            return None
        idx = prefix.rfind("/node_modules/")
        prefix = prefix[:idx] if idx >= 0 else ""


def _npm_entry_edges(info: dict) -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    for section, scope in _DEPENDENCY_SECTION_SCOPES:
        declared = info.get(section)
        if not isinstance(declared, dict):
            continue
        edges.extend((str(dep_name), scope) for dep_name in declared)
    return edges


def _npm_workspace_edges(entries: dict) -> list[tuple[str, str]]:
    """Workspace members as root edges, so a member's dependencies are attributed to it.

    The root entry of a workspace lockfile lists no edge to its members; they
    appear only as top-level ``node_modules/<member>`` symlinks.
    """
    return [
        (_npm_lock_entry_name(path), "runtime")
        for path, info in entries.items()
        if isinstance(info, dict) and info.get("link") and path.startswith("node_modules/") and path.count("node_modules/") == 1
    ]


def _npm_introducing_paths(entries: dict, root_edges: list[tuple[str, str]]) -> dict[str, tuple[int, str | None, str]]:
    """Walk the lockfile's dependency edges from the root.

    Returns ``{install_path: (depth, parent_name, scope)}``. Breadth-first, so
    the first (shortest) path to a package wins — that is the one an engineer
    would act on. Runtime edges are enumerated before dev edges at every node,
    so a package reachable both ways is reported as runtime.
    """
    resolved: dict[str, tuple[int, str | None, str]] = {}
    queue: list[tuple[str, int, str | None, str]] = []

    for dep_name, scope in root_edges:
        target = _npm_resolve_install_path(entries, "", dep_name)
        if target is not None and target not in resolved:
            resolved[target] = (0, None, scope)
            queue.append((target, 0, None, scope))

    head = 0
    while head < len(queue):
        path, depth, _parent, scope = queue[head]
        head += 1
        info = entries.get(path) or {}
        if info.get("link") and isinstance(info.get("resolved"), str):
            # Workspace symlink: the real dependency edges live at the target.
            info = entries.get(info["resolved"]) or info
        parent_name = str(info.get("name") or _npm_lock_entry_name(path))
        for dep_name, edge_scope in _npm_entry_edges(info):
            target = _npm_resolve_install_path(entries, path, dep_name)
            if target is None or target in resolved:
                continue  # already reached by a shorter path, or not installed
            child_scope = "dev" if scope == "dev" else edge_scope
            resolved[target] = (depth + 1, parent_name, child_scope)
            queue.append((target, depth + 1, parent_name, child_scope))
    return resolved


def _npm_v1_introducing_paths(entries: dict, root_names: list[tuple[str, str]]) -> dict[str, tuple[int, str | None, str]]:
    """Same walk for a lockfileVersion 1 tree, whose edges live in ``requires``."""
    resolved: dict[str, tuple[int, str | None, str]] = {}
    queue: list[tuple[str, int, str | None, str]] = []
    for name, scope in root_names:
        if name in entries and name not in resolved:
            resolved[name] = (0, None, scope)
            queue.append((name, 0, None, scope))

    head = 0
    while head < len(queue):
        name, depth, _parent, scope = queue[head]
        head += 1
        requires = (entries.get(name) or {}).get("requires")
        if not isinstance(requires, dict):
            continue
        for dep_name in requires:
            if dep_name not in entries or dep_name in resolved:
                continue
            resolved[dep_name] = (depth + 1, name, scope)
            queue.append((dep_name, depth + 1, name, scope))
    return resolved
