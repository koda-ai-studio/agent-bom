"""Link related scanner observations without discarding source findings."""

from __future__ import annotations

from agent_bom.finding import Finding, FindingSource, FindingType


def _normalized_path(value: object) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if text.startswith("file://"):
        text = text[len("file://") :]
    while text.startswith("./"):
        text = text[2:]
    return text


def _code_anchor(finding: Finding) -> tuple[str, int | None, str] | None:
    if not isinstance(finding.evidence, dict):
        return None
    evidence = finding.evidence
    if finding.finding_type is FindingType.SAST:
        path = _normalized_path(evidence.get("file") or finding.asset.location)
        line = evidence.get("line")
        return (path, line if type(line) is int else None, str(evidence.get("rule_id") or "")) if path else None
    if evidence.get("ecosystem") == "sast" and evidence.get("package_name"):
        return (_normalized_path(evidence["package_name"]), None, str(finding.cve_id or ""))
    return None


def _compatible_scope(left: Finding, right: Finding) -> bool:
    # Unknown scope cannot borrow the other observation's repository or commit.
    for aliases in (("repository", "repository_url", "repo_url", "repository_root"), ("repository_commit", "commit_sha", "git_commit")):
        values = [{str(f.evidence[key]) for key in aliases if f.evidence.get(key)} for f in (left, right)]
        if values[0] != values[1] or any(len(value) > 1 for value in values):
            return False
    return all(getattr(left, key) == getattr(right, key) for key in ("provider", "account_ref", "region", "environment"))


def merge_external_code_findings(findings: list[Finding]) -> list[Finding]:
    """Retain every observation and add reviewable, symmetric candidate links.

    A shared CWE or scanner rule is not proof of the same issue. Even an exact
    file/line match preserves both occurrences, vendor severities, remediation
    and evidence. Paths must match exactly; suffixes cannot establish identity.
    The historical function name remains for callers importing this helper.
    """
    anchors = [(f, a) for f in findings if f.source is not FindingSource.EXTERNAL and (a := _code_anchor(f)) is not None]
    for finding in findings:
        if finding.source is not FindingSource.EXTERNAL or finding.finding_type is not FindingType.SAST:
            continue
        anchor = _code_anchor(finding)
        if anchor is None:
            continue
        path, line, rule = anchor
        for native, (native_path, native_line, native_rule) in anchors:
            if path != native_path or not _compatible_scope(native, finding):
                continue
            same_rule = bool(rule) and rule == native_rule
            if native_line is None:
                matches = same_rule
            else:
                matches = native_line == line and (same_rule or bool(set(finding.cwe_ids) & set(native.cwe_ids)))
            if not matches or native.id == finding.id:
                continue
            for left, right in ((native, finding), (finding, native)):
                if right.id not in left.related_findings:
                    left.related_findings.append(right.id)
                receipts = left.evidence.setdefault("correlation_candidates", [])
                receipt = {"finding_id": right.id, "basis": "same_file_rule" if same_rule else "same_file_line_cwe", "status": "candidate"}
                if receipt not in receipts:
                    receipts.append(receipt)
    return findings
