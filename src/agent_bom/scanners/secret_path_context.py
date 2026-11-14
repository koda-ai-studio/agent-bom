"""Documentation/example/test path context for secret findings.

Go ``testdata/`` and JS ``__fixtures__``/``__mocks__`` hold sample inputs beside
the code under test; docs and examples hold illustrative snippets. Unlike
``tests/`` (never scanned), they are scanned and kept: a real credential left
there is still a leak, so the finding is labelled and lowered, not hidden. A
credential a provider confirmed live keeps its severity wherever it sits.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path, PurePosixPath
from typing import TypedDict

from agent_bom.core.path_context import CONTEXT_SEVERITY, classify_path_context, context_downgrade_reason
from agent_bom.scanners.secret_models import SecretFinding

_FIXTURE_DIRS = frozenset({"testdata", "__fixtures__", "__mocks__"})
_CI_PIPELINE_FILES = frozenset({".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml", "bitbucket-pipelines.yml"})
_DSN_HOST_RE = re.compile(r"://[^@\s/]{1,400}@(\[[0-9a-fA-F:.]{2,45}\]|[^\s/:'\"`?]{1,253})")
CI_LOOPBACK_DSN_REASON = (
    "CI service-container connection string on a loopback host; the database lives only for the job, verify the password is a throwaway"
)


def is_ci_pipeline_file(rel_path: str) -> bool:
    """A CI job definition: GitHub workflow, GitLab, Azure Pipelines or Bitbucket pipeline."""
    parts = [part.lower() for part in PurePosixPath(rel_path.replace("\\", "/")).parts]
    if not parts or PurePosixPath(parts[-1]).suffix not in {".yml", ".yaml"}:
        return False
    in_workflows = len(parts) >= 3 and parts[-3:-1] == [".github", "workflows"]
    return in_workflows or parts[-1] in _CI_PIPELINE_FILES or (len(parts) >= 2 and parts[-2] == ".circleci")


def _is_loopback_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def ci_loopback_dsn(rel_path: str, matched: str) -> bool:
    """A connection string to a loopback host inside a CI job definition."""
    if not is_ci_pipeline_file(rel_path):
        return False
    host = _DSN_HOST_RE.search(matched)
    return bool(host and _is_loopback_host(host.group(1)))


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


class CredentialSeverity(TypedDict):
    severity: str
    downgrade_reason: str | None


def credential_severity(rel_path: str, secret_type: str, match: re.Match) -> CredentialSeverity:
    """Critical, except a CI job's throwaway service-container DSN on a loopback host."""
    if secret_type == "Connection String" and ci_loopback_dsn(rel_path, match.group(0)):
        return {"severity": CONTEXT_SEVERITY, "downgrade_reason": CI_LOOPBACK_DSN_REASON}
    return {"severity": "critical", "downgrade_reason": None}
