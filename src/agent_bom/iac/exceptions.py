"""Apply accepted exceptions to IaC scan results without ever deleting evidence.

A covered finding moves to the suppressed list carrying its ``suppression``
record (state, reason, source, origin, owner, expiry, id); severity gates and
policy ``block``/``warn`` rules only see active findings. An expired exception
stops applying, so its finding is active again, and the operator is told. The
exception shapes and parsing live in :mod:`agent_bom.core.iac_exceptions`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

from agent_bom.core.iac_exceptions import IAC_RULE_ID as IAC_RULE_ID
from agent_bom.core.iac_exceptions import ExceptionNotice as ExceptionNotice
from agent_bom.core.iac_exceptions import IaCException as IaCException
from agent_bom.core.iac_exceptions import ResourceSelector as ResourceSelector
from agent_bom.core.iac_exceptions import is_iac_ignore_entry as is_iac_ignore_entry
from agent_bom.core.iac_exceptions import parse_expiry as parse_expiry
from agent_bom.core.iac_exceptions import parse_ignore_entries as parse_ignore_entries
from agent_bom.core.iac_exceptions import parse_resource_selector as parse_resource_selector
from agent_bom.iac.models import IaCFinding

__all__ = [
    "IAC_RULE_ID",
    "ExceptionNotice",
    "ExceptionOutcome",
    "IaCException",
    "InlineLookup",
    "PathLookup",
    "ResourceSelector",
    "apply_iac_exceptions",
    "cwd_relative_paths",
    "expired_message",
    "expiring_message",
    "is_iac_ignore_entry",
    "parse_expiry",
    "parse_ignore_entries",
    "parse_resource_selector",
    "unsuppress",
]


@dataclass
class ExceptionOutcome:
    active: list[IaCFinding]
    suppressed: list[IaCFinding]
    notices: list[ExceptionNotice]


def _today(value: date | None) -> date:
    return value or datetime.now(timezone.utc).date()


InlineLookup = Callable[[IaCFinding], tuple[IaCException | None, ExceptionNotice | None]]
PathLookup = Callable[[IaCFinding], tuple[str, ...]]


def _default_paths(finding: IaCFinding) -> tuple[str, ...]:
    return tuple(dict.fromkeys(p for p in (finding.repository_relative_path, finding.file_path) if p))


def apply_iac_exceptions(
    findings: Iterable[IaCFinding],
    exceptions: Iterable[IaCException],
    *,
    inline: InlineLookup | None = None,
    paths: PathLookup | None = None,
    today: date | None = None,
) -> ExceptionOutcome:
    """Split findings into active and suppressed; expired or invalid exceptions are reported, never applied."""
    day = _today(today)
    declared = list(exceptions)
    path_lookup = paths or _default_paths
    outcome = ExceptionOutcome(active=[], suppressed=[], notices=[])
    seen: set[tuple[str, str]] = set()

    def notify(notice: ExceptionNotice) -> None:
        if (notice.kind, notice.exception_id) not in seen:
            seen.add((notice.kind, notice.exception_id))
            outcome.notices.append(notice)

    for finding in findings:
        candidates: list[IaCException] = []
        if inline is not None:
            marker, problem = inline(finding)
            if problem is not None:
                notify(problem)
            if marker is not None:
                candidates.append(marker)
        finding_paths = path_lookup(finding)
        candidates.extend(exc for exc in declared if exc.covers(finding, finding_paths))
        chosen = next((exc for exc in candidates if not exc.is_expired(day)), None)
        for exc in candidates:
            if exc.is_expired(day):
                notify(ExceptionNotice.about("expired", exc, expired_message(exc)))
        if chosen is None:
            outcome.active.append(finding)
            continue
        finding.suppression = chosen.record(day)
        outcome.suppressed.append(finding)
        if chosen.expiring_soon(day):
            notify(ExceptionNotice.about("expiring", chosen, expiring_message(chosen, day)))
    return outcome


def _owner_suffix(exc: IaCException) -> str:
    return f"; owner {exc.owner}" if exc.owner else ""


def expired_message(exc: IaCException) -> str:
    expiry = exc.expires.isoformat() if exc.expires else "?"
    return f"exception for {exc.describe()} expired on {expiry}{_owner_suffix(exc)}; its findings are active again"


def expiring_message(exc: IaCException, today: date) -> str:
    expiry = exc.expires.isoformat() if exc.expires else "?"
    days = (exc.expires - today).days if exc.expires else 0
    return f"exception for {exc.describe()} expires on {expiry} (in {days} day(s)){_owner_suffix(exc)}; renew or fix before then"


def unsuppress(finding: IaCFinding) -> None:
    finding.suppression = None


def cwd_relative_paths(walk_root: Path) -> PathLookup:
    """Match path globs against the scan-root path and the working-directory path of a finding."""
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        cwd = None

    def lookup(finding: IaCFinding) -> tuple[str, ...]:
        found = list(_default_paths(finding))
        if cwd is not None and finding.file_path:
            try:
                found.append((walk_root / finding.file_path).resolve().relative_to(cwd).as_posix())
            except ValueError:
                # Roots outside cwd retain their scan-relative path candidates.
                pass
        return tuple(dict.fromkeys(found))

    return lookup
