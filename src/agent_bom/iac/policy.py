"""Policy-as-code rules for IaC findings: allow, warn or block by rule, resource and environment.

A policy rule is an IaC rule when it sets ``"scope": "iac"`` or any ``iac_*``
condition. Conditions are ANDed:

- ``iac_rule``: rule id or glob (``K8S-001``, ``K8S-*``)
- ``severity_gte``: CRITICAL / HIGH / MEDIUM / LOW
- ``iac_path``: glob on the finding's path
- ``iac_resource_kind`` / ``iac_resource_name`` / ``iac_namespace``: globs on the declared resource
- ``iac_labels``: label subset the resource must carry
- ``iac_environment``: environment the finding belongs to (see :meth:`IaCPolicy.environment_of`)

Actions: ``block`` (or ``fail``) fails the gate, ``warn`` reports, ``allow``
accepts the finding as an exception (``reason`` required, optional ``owner`` and
``expires``), retained with the same suppression record as any other exception.
A ``block`` rule with ``"waivable": false`` also rejects inline, ignore-file and
policy-allow exceptions for what it matches; only an approved tenant exception
can waive it.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from agent_bom.core.iac_exceptions import (
    ExceptionNotice,
    IaCException,
    ResourceSelector,
    is_iac_policy_rule,
    parse_expiry,
)
from agent_bom.core.severity import SEVERITY_POLICY_ORDER
from agent_bom.iac.exceptions import ExceptionOutcome, PathLookup, unsuppress
from agent_bom.iac.models import IaCFinding

_ENVIRONMENT_LABELS = ("environment", "env")
_REPO_LOCAL_SOURCES = frozenset({"inline", "ignore_file", "policy"})


@dataclass
class IaCPolicy:
    name: str
    rules: list[dict[str, Any]]
    environments: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_policy(cls, policy: Mapping[str, Any] | None) -> IaCPolicy | None:
        if not policy:
            return None
        rules = [dict(r) for r in policy.get("rules", []) if isinstance(r, Mapping) and is_iac_policy_rule(r)]
        if not rules:
            return None
        environments = {str(k): list(v) for k, v in (policy.get("environments") or {}).items()}
        return cls(name=str(policy.get("name") or "unnamed"), rules=rules, environments=environments)

    def environment_of(self, finding: IaCFinding, paths: tuple[str, ...]) -> str | None:
        """The policy's ``environments`` path globs first, then an ``environment``/``env`` resource label."""
        for name, globs in self.environments.items():
            if any(fnmatch.fnmatchcase(path, glob) for glob in globs for path in paths):
                return name
        labels = finding.resource.labels if finding.resource else {}
        return next((labels[key] for key in _ENVIRONMENT_LABELS if labels.get(key)), None)

    def _matches(self, rule: Mapping[str, Any], finding: IaCFinding, paths: tuple[str, ...]) -> bool:
        if not fnmatch.fnmatchcase(finding.rule_id.upper(), str(rule.get("iac_rule", "*")).upper()):
            return False
        if "severity_gte" in rule:
            threshold = SEVERITY_POLICY_ORDER.get(str(rule["severity_gte"]).upper(), 0)
            if SEVERITY_POLICY_ORDER.get(finding.severity.upper(), 0) < threshold:
                return False
        if "iac_path" in rule and not any(fnmatch.fnmatchcase(path, rule["iac_path"]) for path in paths):
            return False
        if not _selector(rule).matches(finding.resource) and _has_resource_conditions(rule):
            return False
        return "iac_environment" not in rule or self.environment_of(finding, paths) == rule["iac_environment"]

    def allow_exceptions(self, paths: PathLookup) -> list[IaCException]:
        """``allow`` rules as exceptions: same matching, same suppression record, same expiry handling."""
        exceptions: list[IaCException] = []
        for rule in self.rules:
            if rule.get("action") != "allow":
                continue
            exceptions.append(
                IaCException(
                    rule=str(rule.get("iac_rule", "*")).upper(),
                    reason=str(rule.get("reason") or rule.get("description")),
                    source="policy",
                    origin=f"policy:{self.name}#{rule.get('id')}",
                    owner=rule.get("owner"),
                    expires=parse_expiry(rule["expires"]) if rule.get("expires") is not None else None,
                    predicate=self._predicate(rule, paths),
                )
            )
        return exceptions

    def _predicate(self, rule: Mapping[str, Any], paths: PathLookup) -> Callable[[IaCFinding], bool]:
        def predicate(finding: IaCFinding) -> bool:
            return self._matches(rule, finding, paths(finding))

        return predicate

    def evaluate(self, outcome: ExceptionOutcome, paths: PathLookup) -> dict[str, Any]:
        """Apply ``block``/``warn`` to active findings; non-waivable blocks first reject repo-local exceptions."""
        for rule in self.rules:
            if rule.get("action", "block") in {"block", "fail"} and rule.get("waivable") is False:
                self._reject_exceptions(rule, outcome, paths)
        violations: list[dict[str, Any]] = []
        for rule in self.rules:
            action = "fail" if rule.get("action", "block") in {"block", "fail"} else str(rule.get("action"))
            if action == "allow":
                continue
            for finding in outcome.active:
                finding_paths = paths(finding)
                if self._matches(rule, finding, finding_paths):
                    violations.append(self._violation(rule, action, finding, finding_paths))
        allowed = [
            {
                "rule_id": f.suppression["origin"].rsplit("#", 1)[-1],
                "iac_rule_id": f.rule_id,
                "file_path": f.file_path,
                "line_number": f.line_number,
            }
            for f in outcome.suppressed
            if f.suppression and f.suppression.get("source") == "policy"
        ]
        failures = [v for v in violations if v["action"] == "fail"]
        return {
            "policy_name": self.name,
            "violations": violations,
            "failures": failures,
            "warnings": [v for v in violations if v["action"] == "warn"],
            "allowed": allowed,
            "passed": not failures,
        }

    def _reject_exceptions(self, rule: Mapping[str, Any], outcome: ExceptionOutcome, paths: PathLookup) -> None:
        kept: list[IaCFinding] = []
        for finding in outcome.suppressed:
            record = finding.suppression or {}
            if record.get("source") in _REPO_LOCAL_SOURCES and self._matches(rule, finding, paths(finding)):
                exc = IaCException(
                    rule=finding.rule_id,
                    reason=str(record.get("reason") or ""),
                    source=record.get("source", "inline"),
                    origin=str(record.get("origin") or ""),
                    owner=record.get("owner"),
                    exception_id=str(record.get("exception_id") or ""),
                )
                message = f"exception for {exc.describe()} rejected: policy rule '{rule.get('id')}' is not waivable"
                notice = ExceptionNotice.about("rejected", exc, message)
                if notice not in outcome.notices:
                    outcome.notices.append(notice)
                unsuppress(finding)
                outcome.active.append(finding)
            else:
                kept.append(finding)
        outcome.suppressed[:] = kept

    def _violation(self, rule: Mapping[str, Any], action: str, finding: IaCFinding, paths: tuple[str, ...]) -> dict[str, Any]:
        resource = finding.resource.to_dict() if finding.resource else None
        where = f"{finding.file_path}:{finding.line_number}"
        if resource:
            where += f" {resource['kind']}/{resource['name']}"
        return {
            "rule_id": rule.get("id"),
            "rule_description": rule.get("description", ""),
            "action": action,
            "scope": "iac",
            "vulnerability_id": finding.rule_id,
            "iac_rule_id": finding.rule_id,
            "severity": finding.severity,
            "package": where,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "resource": resource,
            "environment": self.environment_of(finding, paths),
        }


def _has_resource_conditions(rule: Mapping[str, Any]) -> bool:
    return any(key in rule for key in ("iac_resource_kind", "iac_resource_name", "iac_namespace", "iac_labels"))


def _selector(rule: Mapping[str, Any]) -> ResourceSelector:
    labels = rule.get("iac_labels") or {}
    return ResourceSelector(
        kind=rule.get("iac_resource_kind"),
        name=rule.get("iac_resource_name"),
        namespace=rule.get("iac_namespace"),
        labels=tuple(sorted((str(k), str(v)) for k, v in labels.items())),
    )


def iac_policy_failed(policy_result: Mapping[str, Any] | None) -> bool:
    return bool(policy_result and policy_result.get("failures"))
