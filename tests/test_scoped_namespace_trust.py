"""A scoped leaf name is not evidence of impersonating an unscoped package."""

import pytest

from agent_bom.malicious import check_dependency_confusion, check_typosquat
from agent_bom.models import Package


@pytest.mark.parametrize("scope", ["actions", "npmcli", "prettier", "independent-team"])
@pytest.mark.parametrize("leaf", ["exec", "redact", "query", "sync", "expresss"])
def test_leaf_similarity_does_not_cross_namespace_boundary(scope, leaf):
    assert check_typosquat(f"@{scope}/{leaf}", "npm") is None


def test_scoped_private_name_is_not_dependency_confusion_evidence():
    assert check_dependency_confusion(Package(name="@mui/private-theming", version="5.17.1", ecosystem="npm")) is None
