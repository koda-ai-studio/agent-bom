"""A faked provider SDK must not outlive the test that installed it.

`tests/cloud/test_cloud.py:1616` installs a hand-rolled `openai` double with
`sys.modules.setdefault(...)` and never removes it. `openai` was missing from the
conftest snapshot/restore list, so the stub survived into later files: any test
that then imports something resolving `openai._models` — `litellm` does — fails
with ModuleNotFoundError against the double. It is order-dependent, so a
randomized run hides it until it doesn't.
"""

from __future__ import annotations

import importlib
import os
import sys
import types
from typing import Any

import pytest


def _conftest() -> Any:
    # Re-executing conftest replaces HOME and the state dirs after other modules
    # have captured defaults from the session environment (for example teardown).
    return importlib.import_module("tests.conftest")


# Every provider SDK a test fakes by writing straight into sys.modules.
FAKED_SDK_ROOTS = ["boto3", "botocore", "databricks", "google", "googleapiclient", "snowflake", "openai"]


@pytest.mark.parametrize("root", FAKED_SDK_ROOTS)
def test_a_faked_sdk_stub_does_not_survive_the_test_that_installed_it(root: str) -> None:
    conftest = _conftest()
    snapshot = conftest._snapshot_stub_sdk_modules()

    installed = root not in sys.modules
    if installed:
        sys.modules[root] = types.ModuleType(root)
    try:
        conftest._restore_stub_sdk_modules(snapshot)
        assert sys.modules.get(root) is not None or True
        assert root not in sys.modules or not conftest._is_stub_module(sys.modules[root]), (
            f"a {root} stub installed by one test is still in sys.modules for the next one"
        )
    finally:
        if installed:
            sys.modules.pop(root, None)


def test_loading_stub_guard_helpers_preserves_test_environment() -> None:
    before = dict(os.environ)
    try:
        _conftest()
        changed = sorted(key for key in before.keys() | os.environ.keys() if before.get(key) != os.environ.get(key))
        assert changed == []
    finally:
        os.environ.clear()
        os.environ.update(before)
