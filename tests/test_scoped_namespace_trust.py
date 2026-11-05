"""Known namespaces avoid leaf false positives; unknown scopes retain typo warnings."""

import pytest

from agent_bom.malicious import check_dependency_confusion, check_typosquat
from agent_bom.models import Package


@pytest.mark.parametrize("scope", ["actions", "npmcli", "prettier"])
@pytest.mark.parametrize("leaf", ["exec", "redact", "query", "sync", "expresss"])
def test_known_namespace_does_not_inherit_unscoped_leaf_false_positives(scope, leaf):
    assert check_typosquat(f"@{scope}/{leaf}", "npm") is None


def test_scoped_private_name_is_not_dependency_confusion_evidence():
    assert check_dependency_confusion(Package(name="@mui/private-theming", version="5.17.1", ecosystem="npm")) is None


@pytest.mark.parametrize(
    "leaf,target", [("exec", "execa"), ("redact", "react"), ("query", "jquery"), ("sync", "async"), ("expresss", "express")]
)
def test_unknown_namespace_does_not_blanket_suppress_leaf_typo_warnings(leaf, target):
    assert check_typosquat(f"@independent-team/{leaf}", "npm") == target
