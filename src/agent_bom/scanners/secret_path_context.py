"""Documentation/example/test path context for secret findings.

Go ``testdata/`` and JS ``__fixtures__``/``__mocks__`` hold sample inputs beside
the code under test; docs and examples hold illustrative snippets. Unlike
``tests/`` (never scanned), they are scanned and kept: a real credential left
there is still a leak, so the finding is labelled and lowered, not hidden. A
credential a provider confirmed live keeps its severity wherever it sits.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.core.path_context import CONTEXT_SEVERITY, classify_path_context, context_downgrade_reason
from agent_bom.scanners.secret_models import SecretFinding

_FIXTURE_DIRS = frozenset({"testdata", "__fixtures__", "__mocks__"})


def apply_path_context(rel_path: str, findings: list[SecretFinding]) -> list[SecretFinding]:
    """Label findings in documentation/example/test paths and lower them to ``low``."""
    context = classify_path_context(rel_path)
    if context is None:
        return findings
    fixture_dir = next((part for part in Path(rel_path).parts[:-1] if part in _FIXTURE_DIRS), None)
    reason = f"test fixture path ({fixture_dir}); verify the value is synthetic" if fixture_dir else context_downgrade_reason(context)
    for finding in findings:
        finding.path_context = context
        if finding.validation_status == "valid":
            continue
        finding.severity = CONTEXT_SEVERITY
        finding.downgrade_reason = reason
    return findings
