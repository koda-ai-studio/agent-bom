"""The IaC exception and policy contract, with no scanner imports.

An exception says "this rule, at this place, on this resource, is accepted for
this reason until this date". It is declared inline next to the finding
(``# agent-bom: ignore[K8S-001] expires=2026-12-31 owner=platform <reason>``),
in ``.agent-bom-ignore.yaml``, in the tenant exception store (approved through
the API workflow), or by an ``allow`` rule of a policy file. Whatever declares
it, it is one :class:`IaCException` and produces one suppression record.

This module holds the shapes, parsing and validation shared by the CLI, the API
request models, the tenant store and the policy engine. Applying exceptions to
scan results lives in :mod:`agent_bom.iac.exceptions`; evaluating policy rules
in :mod:`agent_bom.iac.policy`. Anything malformed is rejected here, so it can
never suppress a finding.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Literal

from agent_bom.core.severity import SEVERITY_POLICY_ORDER

SUPPRESSION_STATE = "accepted_risk"
EXPIRY_NOTICE_DAYS = 14
ExceptionSource = Literal["inline", "ignore_file", "tenant", "policy"]
NoticeKind = Literal["expired", "expiring", "invalid", "rejected"]

# Rule-id families the IaC scanners emit. Vulnerability ids (CVE-, GHSA-, PYSEC-, GO-, ...) never start with these.
IAC_RULE_ID = re.compile(r"^(TF|K8S|DOCKER|DOCKERD|CFN|HELM|DCM|COMPOSE|DBT|GHA|IAM)-[A-Z0-9][A-Z0-9-]*$", re.IGNORECASE)
_RULE_PATTERN = re.compile(r"^[A-Za-z0-9*?_\-\[\]]{1,80}$")
_ENTRY_KEYS = frozenset({"id", "rule", "type", "path", "resource", "expires", "owner", "reason"})
_RESOURCE_KEYS = frozenset({"kind", "name", "namespace", "labels"})
_IAC_TYPES = frozenset({"iac", "iac-misconfiguration", "iac_misconfiguration"})
_MAX_TEXT = 500
MAX_REASON = 500
_MAX_LABELS = 32


@dataclass(frozen=True)
class ResourceSelector:
    """Narrows an exception to declared resources; every given field must match."""

    kind: str | None = None
    name: str | None = None
    namespace: str | None = None
    labels: tuple[tuple[str, str], ...] = ()

    def matches(self, resource: Any) -> bool:
        if resource is None:
            return False
        if self.kind is not None and not fnmatch.fnmatchcase(resource.kind.lower(), self.kind.lower()):
            return False
        if self.name is not None and not fnmatch.fnmatchcase(resource.name, self.name):
            return False
        if self.namespace is not None and not fnmatch.fnmatchcase(resource.namespace, self.namespace):
            return False
        return all(resource.labels.get(key) == value for key, value in self.labels)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            key: value for key, value in (("kind", self.kind), ("name", self.name), ("namespace", self.namespace)) if value
        }
        if self.labels:
            out["labels"] = dict(self.labels)
        return out


@dataclass(frozen=True)
class IaCException:
    """One accepted exception, whatever declared it."""

    rule: str
    reason: str
    source: ExceptionSource
    origin: str
    path: str | None = None
    resource: ResourceSelector | None = None
    expires: date | None = None
    owner: str | None = None
    approved_by: str | None = None
    exception_id: str = ""
    # Extra condition a policy ``allow`` rule adds (severity, environment); not part of identity.
    predicate: Callable[[Any], bool] | None = field(default=None, compare=False, hash=False, repr=False)

    def __post_init__(self) -> None:
        if not self.exception_id:
            selector = self.resource.to_dict() if self.resource else {}
            basis = "|".join([self.source, self.origin, self.rule.upper(), self.path or "", repr(sorted(selector.items()))])
            object.__setattr__(self, "exception_id", "iacx-" + hashlib.sha256(basis.encode()).hexdigest()[:16])

    def covers(self, finding: Any, paths: Iterable[str]) -> bool:
        if not fnmatch.fnmatchcase(finding.rule_id.upper(), self.rule.upper()):
            return False
        if self.path is not None and not any(fnmatch.fnmatchcase(path, self.path) for path in paths):
            return False
        if self.resource is not None and not self.resource.matches(finding.resource):
            return False
        return self.predicate is None or self.predicate(finding)

    def is_expired(self, today: date) -> bool:
        return self.expires is not None and today > self.expires

    def expiring_soon(self, today: date) -> bool:
        return self.expires is not None and not self.is_expired(today) and (self.expires - today).days <= EXPIRY_NOTICE_DAYS

    def record(self, today: date) -> dict[str, Any]:
        """The suppression record a covered finding carries into every export."""
        return {
            "state": SUPPRESSION_STATE,
            "reason": self.reason,
            "source": self.source,
            "origin": self.origin,
            "owner": self.owner,
            "expires": self.expires.isoformat() if self.expires else None,
            "expiring_soon": self.expiring_soon(today),
            "approved_by": self.approved_by,
            "exception_id": self.exception_id,
        }

    def describe(self) -> str:
        return f"{self.rule} ({self.source} {self.origin})"


@dataclass(frozen=True)
class ExceptionNotice:
    kind: NoticeKind
    message: str
    exception_id: str
    rule: str
    source: str
    origin: str
    owner: str | None = None
    expires: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "exception_id": self.exception_id,
            "rule": self.rule,
            "source": self.source,
            "origin": self.origin,
            "owner": self.owner,
            "expires": self.expires,
        }

    @classmethod
    def about(cls, kind: NoticeKind, exc: IaCException, message: str) -> ExceptionNotice:
        return cls(
            kind=kind,
            message=message,
            exception_id=exc.exception_id,
            rule=exc.rule,
            source=exc.source,
            origin=exc.origin,
            owner=exc.owner,
            expires=exc.expires.isoformat() if exc.expires else None,
        )


# ── parsing ─────────────────────────────────────────────────────────────────


def parse_expiry(value: Any) -> date:
    """``YYYY-MM-DD`` (or a YAML date) to a date; anything else is an error."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return datetime.strptime(value.strip(), "%Y-%m-%d").date()
        except ValueError:
            pass
    raise ValueError(f"expires must be a YYYY-MM-DD date, got {value!r}")


def is_iac_ignore_entry(entry: Any) -> bool:
    """True for ignore-file entries about IaC rules rather than vulnerabilities."""
    if not isinstance(entry, Mapping):
        return False
    if "rule" in entry or "resource" in entry:
        return True
    if str(entry.get("type") or "").strip().lower() in _IAC_TYPES:
        return True
    return bool(IAC_RULE_ID.match(str(entry.get("id") or "").strip()))


def _text(entry: Mapping[str, Any], key: str, *, required: bool = False) -> str | None:
    value = entry.get(key)
    if value is None:
        if required:
            raise ValueError(f"'{key}' is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    value = value.strip()
    if required and not value:
        raise ValueError(f"'{key}' is required and must not be empty")
    if len(value) > _MAX_TEXT:
        raise ValueError(f"'{key}' is longer than {_MAX_TEXT} characters")
    return value or None


def parse_resource_selector(raw: Any) -> ResourceSelector:
    if not isinstance(raw, Mapping):
        raise ValueError("'resource' must be a mapping of kind/name/namespace/labels")
    unknown = sorted(set(raw) - _RESOURCE_KEYS)
    if unknown:
        raise ValueError(f"'resource' has unknown key(s) {', '.join(map(str, unknown))}; allowed: kind, name, namespace, labels")
    labels_raw = raw.get("labels") or {}
    if isinstance(labels_raw, Mapping) and len(labels_raw) > _MAX_LABELS:
        raise ValueError(f"'resource.labels' has more than {_MAX_LABELS} labels")
    if not isinstance(labels_raw, Mapping) or not all(
        isinstance(k, str) and isinstance(v, (str, int, bool)) for k, v in labels_raw.items()
    ):
        raise ValueError("'resource.labels' must be a mapping of label name to value")
    selector = ResourceSelector(
        kind=_text(raw, "kind"),
        name=_text(raw, "name"),
        namespace=_text(raw, "namespace"),
        labels=tuple(sorted((key, str(value).lower() if isinstance(value, bool) else str(value)) for key, value in labels_raw.items())),
    )
    if selector == ResourceSelector():
        raise ValueError("'resource' must set at least one of kind, name, namespace, labels")
    return selector


def _rule_of(entry: Mapping[str, Any]) -> str:
    rule = _text(entry, "rule")
    entry_id = _text(entry, "id")
    if rule and entry_id and rule.upper() != entry_id.upper():
        raise ValueError("'rule' and 'id' disagree; use one")
    chosen = rule or entry_id
    if not chosen:
        raise ValueError("'rule' (an IaC rule id such as K8S-001, or a glob such as K8S-*) is required")
    if not _RULE_PATTERN.match(chosen):
        raise ValueError(f"'rule' {chosen!r} is not an IaC rule id or glob")
    return chosen.upper()


def parse_ignore_entry(entry: Mapping[str, Any], *, origin: str) -> IaCException:
    unknown = sorted(set(map(str, entry)) - _ENTRY_KEYS)
    if unknown:
        raise ValueError(f"unknown key(s) {', '.join(unknown)}; allowed: {', '.join(sorted(_ENTRY_KEYS))}")
    entry_type = str(entry.get("type") or "iac").strip().lower()
    if entry_type not in _IAC_TYPES:
        raise ValueError(f"'type' {entry_type!r} cannot be combined with an IaC rule; use type: iac")
    rule = _rule_of(entry)
    reason = _text(entry, "reason", required=True)
    path = _text(entry, "path")
    resource = parse_resource_selector(entry["resource"]) if entry.get("resource") is not None else None
    if not rule.strip("*?") and path is None and resource is None:
        raise ValueError("a wildcard rule needs a path or resource scope; it would accept every IaC finding")
    expires = parse_expiry(entry["expires"]) if entry.get("expires") is not None else None
    return IaCException(
        rule=rule,
        reason=reason or "",
        source="ignore_file",
        origin=origin,
        path=path,
        resource=resource,
        expires=expires,
        owner=_text(entry, "owner"),
    )


def parse_ignore_entries(entries: Iterable[Any], *, origin: str) -> list[IaCException]:
    """Validate the IaC entries of an ignore file; other entries belong to the vulnerability path."""
    exceptions: list[IaCException] = []
    for index, entry in enumerate(entries, start=1):
        if not is_iac_ignore_entry(entry):
            continue
        try:
            exceptions.append(parse_ignore_entry(entry, origin=f"{origin}#{index}"))
        except ValueError as exc:
            label = entry.get("rule") or entry.get("id") or "?"
            raise ValueError(f"{origin}: entry #{index} ({label}): {exc}") from None
    return exceptions


# ── policy rules ────────────────────────────────────────────────────────────

IAC_CONDITION_KEYS = frozenset(
    {"iac_rule", "iac_path", "iac_resource_kind", "iac_resource_name", "iac_namespace", "iac_labels", "iac_environment"}
)
IAC_ACTIONS = frozenset({"allow", "warn", "block", "fail"})
_IAC_RULE_KEYS = IAC_CONDITION_KEYS | {"id", "description", "scope", "action", "severity_gte", "reason", "owner", "expires", "waivable"}


def is_iac_policy_rule(rule: Mapping[str, Any]) -> bool:
    return str(rule.get("scope") or "").lower() == "iac" or any(key in rule for key in IAC_CONDITION_KEYS)


def _validate_conditions(rule: Mapping[str, Any], rid: Any) -> None:
    for key in IAC_CONDITION_KEYS - {"iac_labels"}:
        if key in rule and (not isinstance(rule[key], str) or not rule[key].strip()):
            raise ValueError(f"IaC rule '{rid}' field '{key}' must be a non-empty string")
    labels = rule.get("iac_labels")
    if labels is not None and (not isinstance(labels, Mapping) or not labels or not all(isinstance(k, str) for k in labels)):
        raise ValueError(f"IaC rule '{rid}' field 'iac_labels' must be a non-empty mapping of label to value")
    severity = rule.get("severity_gte")
    if severity is not None and (not isinstance(severity, str) or severity.upper() not in SEVERITY_POLICY_ORDER):
        raise ValueError(f"IaC rule '{rid}' severity_gte must be one of CRITICAL, HIGH, MEDIUM, LOW")


def _validate_allow(rule: Mapping[str, Any], rid: Any) -> None:
    reason = rule.get("reason") or rule.get("description")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(f"IaC allow rule '{rid}' needs a 'reason' (recorded on every finding it accepts)")
    if not any(key in rule for key in IAC_CONDITION_KEYS - {"iac_rule"}) and not str(rule.get("iac_rule", "*")).strip("*?"):
        raise ValueError(f"IaC allow rule '{rid}' needs an exact iac_rule or a path/resource/environment scope")
    if "owner" in rule and not isinstance(rule["owner"], str):
        raise ValueError(f"IaC allow rule '{rid}' field 'owner' must be a string")
    if rule.get("expires") is not None:
        try:
            parse_expiry(rule["expires"])
        except ValueError as exc:
            raise ValueError(f"IaC allow rule '{rid}': {exc}") from None


def _validate_rule(rule: Mapping[str, Any]) -> None:
    rid = rule.get("id")
    if not rid:
        raise ValueError("IaC policy rule missing 'id'")
    unknown = sorted(set(map(str, rule)) - _IAC_RULE_KEYS)
    if unknown:
        raise ValueError(f"IaC rule '{rid}' has unknown field(s) {', '.join(unknown)}")
    action = rule.get("action", "block")
    if action not in IAC_ACTIONS:
        raise ValueError(f"IaC rule '{rid}' action must be 'allow', 'warn' or 'block'")
    _validate_conditions(rule, rid)
    if "waivable" in rule and (not isinstance(rule["waivable"], bool) or action not in {"block", "fail"}):
        raise ValueError(f"IaC rule '{rid}' field 'waivable' must be a boolean on a block rule")
    if action == "allow":
        _validate_allow(rule, rid)


def validate_iac_policy(policy: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` for malformed IaC rules or ``environments``."""
    environments = policy.get("environments")
    if environments is not None:
        if not isinstance(environments, Mapping):
            raise ValueError("Policy 'environments' must map an environment name to a list of path globs")
        for name, globs in environments.items():
            if not isinstance(globs, list) or not all(isinstance(g, str) and g.strip() for g in globs):
                raise ValueError(f"Policy environment '{name}' must be a list of path globs")
    for rule in policy.get("rules", []):
        if isinstance(rule, Mapping) and is_iac_policy_rule(rule):
            _validate_rule(rule)


def vulnerability_rules(rules: Iterable[Any]) -> Iterator[tuple[int, Any]]:
    """``(index, rule)`` for every rule that is not an IaC rule; IaC rules are judged at scan time."""
    for index, rule in enumerate(rules):
        if not (isinstance(rule, Mapping) and is_iac_policy_rule(rule)):
            yield index, rule


def scan_time_iac_violations(report: object | None) -> list[dict[str, Any]]:
    """IaC policy violations recorded when the IaC scan ran, so exceptions and exports agree with the gate."""
    data = getattr(report, "iac_findings_data", None) if report is not None else None
    outcome = data.get("policy") if isinstance(data, dict) else None
    if not isinstance(outcome, dict):
        return []
    return [dict(v) for v in outcome.get("violations", []) if isinstance(v, dict)]
