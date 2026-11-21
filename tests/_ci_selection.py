"""Collect only the test modules a CI shard selected, in one pass over the test root.

Given hundreds of module paths as arguments, pytest re-collects the enclosing
package directory once per argument (``Session.collect`` does not reuse a
directory's collection when the remaining part is a single file), so a
390-module shard spent 90-170 s collecting before its first test ran.

CI instead passes the test root once and lists the shard's modules, one path
per line relative to the rootdir, in the file named by
``AGENT_BOM_PYTEST_SELECTION``. Every other test module, and every directory
that holds no selected module, is ignored before it is imported, so the shard
collects the same items it would from the file arguments.

The variable is removed from the environment once read, so a test that starts
its own pytest is never filtered by the shard; pytest-xdist workers receive the
listing through their ``workerinput`` instead.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

SELECTION_ENV = "AGENT_BOM_PYTEST_SELECTION"
_SELECTED = pytest.StashKey[frozenset[Path]]()
_ANCESTORS = pytest.StashKey[frozenset[Path]]()
_LISTING = pytest.StashKey[str]()
_WORKER_INPUT = "agent_bom_pytest_selection"


def _read_selection(config: pytest.Config, listing: Path) -> frozenset[Path]:
    names = [line.strip() for line in listing.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not names:
        raise pytest.UsageError(f"{SELECTION_ENV}={listing} selects no test modules")
    paths = {name: config.rootpath / name for name in names}
    invalid = sorted(name for name, path in paths.items() if not path.is_file() or not path.name.startswith("test_"))
    if invalid:
        raise pytest.UsageError(f"{SELECTION_ENV} names missing or non-test modules: {', '.join(invalid)}")
    return frozenset(path.resolve() for path in paths.values())


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    workerinput = getattr(config, "workerinput", None)
    listing = os.environ.pop(SELECTION_ENV, None)
    if workerinput is not None:
        listing = workerinput.get(_WORKER_INPUT)
    if not listing:
        return
    selected = _read_selection(config, Path(listing))
    config.stash[_LISTING] = listing
    config.stash[_SELECTED] = selected
    config.stash[_ANCESTORS] = frozenset(parent for path in selected for parent in path.parents)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node) -> None:  # type: ignore[no-untyped-def]
    """Hand the controller's selection to each pytest-xdist worker."""
    listing = node.config.stash.get(_LISTING, None)
    if listing:
        node.workerinput[_WORKER_INPUT] = listing


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    selected = config.stash.get(_SELECTED, None)
    if selected is None:
        return None
    path = collection_path.resolve()
    if path.is_dir():
        return None if path in config.stash[_ANCESTORS] else True
    if path.suffix == ".py" and path.name not in {"__init__.py", "conftest.py"} and path not in selected:
        return True
    return None
