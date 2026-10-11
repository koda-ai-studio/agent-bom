"""Serialized report contracts shared by producers and the report envelope.

These TypedDicts describe existing wire shapes; they do not coerce, discard or
validate evidence during a scan. Strict producer contract tests and static type
checking guard the boundary. Provider-specific evidence remains extensible.
"""

from __future__ import annotations

from typing import Any

try:
    from typing_extensions import NotRequired, TypedDict
except ImportError:
    # The data-model atlas also runs under python -S, without installed extras.
    from typing import NotRequired, TypedDict


class BenchmarkCheckPayload(TypedDict):
    check_id: str
    title: str
    status: str
    severity: str
    evidence: str
    recommendation: str
    cis_section: str
    score: NotRequired[float]
    resource_ids: NotRequired[list[str]]
    remediation: NotRequired[dict[str, Any]]
    account_id: NotRequired[str]
    subscription_id: NotRequired[str]
    project_id: NotRequired[str]
    network_exposure: NotRequired[list[dict[str, Any]]]
    attack_techniques: NotRequired[list[str]]
    maestro_layer: NotRequired[str]


class BenchmarkPayload(TypedDict):
    benchmark: str
    benchmark_version: str
    overall_score: NotRequired[float]
    passed: int
    failed: int
    total: int
    pass_rate: float
    checks: list[BenchmarkCheckPayload]
    benchmark_manifest: NotRequired[dict[str, Any]]
    account_id: NotRequired[str]
    account: NotRequired[str]
    subscription_id: NotRequired[str]
    project_id: NotRequired[str]
    region: NotRequired[str]
    accounts_scanned: NotRequired[list[str]]
    regions_scanned: NotRequired[list[str]]
    subscriptions_scanned: NotRequired[list[str]]
    projects_scanned: NotRequired[list[str]]
    completeness: NotRequired[str]
    scope: NotRequired[str]
    warnings: NotRequired[list[str]]
    errored: NotRequired[int]
    no_data: NotRequired[int]
    not_applicable: NotRequired[int]
    evaluated: NotRequired[int]
    source_health: NotRequired[dict[str, dict[str, Any]]]
    metadata: NotRequired[dict[str, Any]]


class OSVResponseCachePayload(TypedDict):
    packages: int
    live_queries: int


class VulnerabilityFreshnessPayload(TypedDict):
    mode: str
    sources: list[str]
    last_updated: str | None
    age_hours: int | None
    age_days: int | None
    record_count: int
    stale: bool
    danger: bool
    max_age_hours: int
    osv_response_cache: NotRequired[OSVResponseCachePayload]


class CorrelatedFindingPayload(TypedDict):
    vulnerability_id: str
    severity: str
    cvss_score: float
    epss_score: float
    is_kev: bool
    package_name: str
    package_version: str
    tool_name: str
    server_name: str
    call_count: int
    last_called: str
    first_called: str
    was_blocked: bool
    risk_amplifier: float
    original_risk_score: float
    correlated_risk_score: float
    affected_agents: list[str]
    exposed_credentials: list[str]


class UncalledVulnerableToolPayload(TypedDict):
    vulnerability_id: str
    tool_name: str
    severity: str
    risk_score: float
    note: str


class RuntimeCorrelationSummary(TypedDict):
    called_and_vulnerable: int
    highest_correlated_risk: float
    kev_tools_called: int


class RuntimeCorrelationPayload(TypedDict):
    timestamp: str
    total_tool_calls: int
    unique_tools_called: int
    vulnerable_tools_called: int
    correlated_findings: list[CorrelatedFindingPayload]
    uncalled_vulnerable_tools: list[UncalledVulnerableToolPayload]
    summary: RuntimeCorrelationSummary


class LicenseFindingPayload(TypedDict):
    package_name: str
    package_version: str
    ecosystem: str
    license_id: str
    license_expression: str
    category: str
    risk_level: str
    reason: str
    agents: list[str]


class LicenseCoveragePayload(TypedDict):
    evaluated: int
    unknown: int
    total: int
    percent: float


class LicenseSummaryPayload(TypedDict, total=False):
    total_packages: int
    findings_count: int
    unknown_count: int
    compliant: bool
    status: str
    coverage: LicenseCoveragePayload
    by_category: dict[str, int]
    by_risk: dict[str, int]


class LicenseReportPayload(TypedDict):
    compliant: bool
    status: str
    coverage: LicenseCoveragePayload
    total_packages: int
    unknown_count: int
    summary: LicenseSummaryPayload
    findings: list[LicenseFindingPayload]


class VexStatementPayload(TypedDict):
    vulnerability_id: str
    status: str
    justification: str | None
    impact_statement: str | None
    action_statement: str | None
    products: list[str]
    timestamp: str
    author: str


class VexStatsPayload(TypedDict):
    total_statements: int
    affected: int
    not_affected: int
    fixed: int
    under_investigation: int


class VexReportPayload(TypedDict):
    metadata: NotRequired[dict[str, Any]]
    statements: list[VexStatementPayload]
    stats: VexStatsPayload
