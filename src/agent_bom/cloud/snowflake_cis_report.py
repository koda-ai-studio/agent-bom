"""Aggregated result model for the CIS Snowflake Benchmark."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_bom.domain.report_payloads import BenchmarkPayload

from .aws_cis_benchmark import CheckStatus, CISCheckResult


@dataclass
class SnowflakeCISReport:
    """Aggregated CIS Snowflake Benchmark results."""

    benchmark_version: str = "1.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    account: str = ""
    source_health: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def errored(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.ERROR)

    @property
    def not_applicable(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.NOT_APPLICABLE)

    @property
    def no_data(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.NO_DATA)

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.evaluated * 100) if self.evaluated else 0.0

    def to_dict(self) -> BenchmarkPayload:
        from agent_bom.cloud.benchmark_manifests import benchmark_manifest
        from agent_bom.mitre_attack import tag_cis_check

        return {
            "benchmark": "CIS Snowflake Foundations",
            "benchmark_version": self.benchmark_version,
            "benchmark_manifest": benchmark_manifest("snowflake"),
            "account": self.account,
            "pass_rate": round(self.pass_rate, 1),
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "not_applicable": self.not_applicable,
            "no_data": self.no_data,
            "evaluated": self.evaluated,
            "total": self.total,
            "source_health": self.source_health,
            "checks": [
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "status": c.status.value,
                    "severity": c.severity,
                    "evidence": c.evidence,
                    "resource_ids": c.resource_ids,
                    "recommendation": c.recommendation,
                    "remediation": c.remediation,
                    "cis_section": c.cis_section,
                    "attack_techniques": tag_cis_check(c),
                }
                for c in self.checks
            ],
        }
