"""Callbacks run after a graph snapshot commits.

A dependency-free registry, so the snapshot writer never imports what reacts to
a commit. A process that serves graph reads registers its warm-up here when its
routes load; a process that only writes snapshots registers nothing.
Callbacks must return quickly and must not raise.
"""

from __future__ import annotations

from typing import Any, Callable

CommitHook = Callable[..., None]

_HOOKS: dict[str, CommitHook] = {}


def register_commit_hook(name: str, hook: CommitHook) -> None:
    _HOOKS[name] = hook


def run_commit_hooks(store_factory: Callable[[], Any], *, tenant_id: str) -> None:
    for hook in list(_HOOKS.values()):
        hook(store_factory, tenant_id=tenant_id)


__all__ = ["register_commit_hook", "run_commit_hooks"]
