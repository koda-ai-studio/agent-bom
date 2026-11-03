"""One IaC run for the CLI: load the operator's exceptions and policy, scan paths, and build the payload."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click

import agent_bom.iac as iac_scanner
from agent_bom.core.iac_exceptions import IaCException, parse_ignore_entries
from agent_bom.iac.exceptions import apply_iac_exceptions
from agent_bom.iac.models import ScanContext, ScanResult, iac_findings_payload, merge_policy_results
from agent_bom.iac.policy import IaCPolicy
from agent_bom.ignores import load_ignore_file
from agent_bom.output.console_iac import print_iac_exceptions
from agent_bom.output.console_render import print_policy_results
from agent_bom.policy import load_policy

_DEFAULT_IGNORE_FILE = ".agent-bom-ignore.yaml"


def load_iac_controls(ignore_file: str | None, policy_path: str | None) -> tuple[tuple[IaCException, ...], IaCPolicy | None]:
    """IaC entries of the ignore file (default ``.agent-bom-ignore.yaml``) and IaC rules of ``--policy``.

    A malformed entry or rule is a usage error: an exception that silently fails
    to load would turn a gate red for no visible reason, and one that silently
    loads too broadly would hide findings.
    """
    try:
        entries = load_ignore_file(ignore_file)
        exceptions = parse_ignore_entries(entries, origin=Path(ignore_file or _DEFAULT_IGNORE_FILE).name)
        policy = IaCPolicy.from_policy(load_policy(policy_path)) if policy_path else None
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    return tuple(exceptions), policy


@dataclass
class IaCRun:
    """Results of every IaC path in one CLI invocation, with exceptions and policy applied once per path."""

    context: ScanContext
    findings: list[Any] = field(default_factory=list)
    suppressed: list[Any] = field(default_factory=list)
    notices: list[Any] = field(default_factory=list)
    verdicts: list[Any] = field(default_factory=list)
    policy_results: list[dict[str, Any] | None] = field(default_factory=list)

    @classmethod
    def load(cls, *, deployment_mode: str, ignore_file: str | None, policy_path: str | None) -> IaCRun:
        exceptions, policy = load_iac_controls(ignore_file, policy_path)
        return cls(context=ScanContext(deployment_mode=deployment_mode, exceptions=exceptions, policy=policy))

    def scan(self, path: str) -> ScanResult:
        result = iac_scanner.scan_iac_with_context(path, self.context)
        self.policy_results.append(result.policy_result)
        self.verdicts.extend(result.verdicts)
        return result

    def add(self, result: ScanResult) -> None:
        """Collect a result after any path re-anchoring."""
        self.findings.extend(result.findings)
        self.suppressed.extend(result.suppressed)
        self._notify(result.notices)

    def add_live(self, findings: list[Any]) -> None:
        """Live cluster posture findings take ignore-file exceptions too (no inline markers or paths there)."""
        outcome = apply_iac_exceptions(findings, self.context.exceptions, today=self.context.today)
        self.findings.extend(outcome.active)
        self.suppressed.extend(outcome.suppressed)
        self._notify(outcome.notices)

    def _notify(self, notices: list[Any]) -> None:
        self.notices.extend(notice for notice in notices if notice not in self.notices)

    @property
    def policy_result(self) -> dict[str, Any] | None:
        return merge_policy_results(self.policy_results)

    def print_exceptions(self, con: Any, *, verbose: bool) -> None:
        print_iac_exceptions(con, self.suppressed, self.notices, verbose=verbose)

    def print_summary(self, con: Any, *, verbose: bool) -> None:
        """Exceptions plus the IaC policy outcome (the focused ``iac`` command has no later policy step)."""
        self.print_exceptions(con, verbose=verbose)
        if self.policy_result is not None:
            print_policy_results(self.policy_result, console=con)

    def payload(self, **extra: Any) -> dict[str, Any]:
        return iac_findings_payload(self.findings, self.suppressed, self.notices, policy=self.policy_result, **extra)
