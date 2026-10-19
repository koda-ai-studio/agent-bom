"""Account-scoped compliance evidence aggregation."""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import urlencode

_CIS_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("aws", ("cis_benchmark", "cis_benchmark_data")),
    ("azure", ("azure_cis_benchmark", "azure_cis_benchmark_data")),
    ("gcp", ("gcp_cis_benchmark", "gcp_cis_benchmark_data")),
    ("snowflake", ("snowflake_cis_benchmark", "snowflake_cis_benchmark_data")),
    # Databricks has no official CIS benchmark: prefer the canonical
    # ``databricks_security`` key, then the deprecated CIS-named aliases.
    ("databricks", ("databricks_security", "databricks_cis_benchmark", "databricks_cis_benchmark_data")),
)


def _split_account_ref(raw: str | None) -> tuple[str, str, str]:
    """Return ``(canonical_ref, provider, bare_account)`` for a path param.

    Canonicalized (trimmed, provider lowercased) so ``AWS:1234`` and ``aws:1234``
    collapse. A value with no ``<provider>:<account>`` shape yields an empty
    provider/account so the endpoint returns an honest empty summary rather than
    raising — the same never-raise contract the #3946 scope filters hold.
    """
    text = (raw or "").strip()
    provider, sep, account = text.partition(":")
    provider = provider.strip().lower()
    account = account.strip()
    if not sep or not provider or not account:
        return "", "", ""
    return f"{provider}:{account}", provider, account


def _account_findings_href(account_ref: str, provider: str, *, domain: str | None = None) -> str:
    """Build a /findings deep-link pre-filtered to this account (and domain)."""
    params: dict[str, str] = {}
    if provider:
        params["provider"] = provider
    if account_ref:
        params["account"] = account_ref
    if domain:
        params["domain"] = domain
    query = urlencode(params)
    return f"/findings?{query}" if query else "/findings"


def _cis_block_account_id(data: dict[str, Any]) -> str:
    """Pull the account/subscription/project id out of a stored CIS block."""
    for key in ("account_id", "subscription_id", "aws_account_id", "project_id"):
        value = str(data.get(key) or "").strip()
        if value:
            return value
    return ""


def _cis_counts(data: dict[str, Any]) -> tuple[int, int]:
    """Return ``(passed, failed)`` for a CIS block, computing from checks if absent."""
    passed = data.get("passed")
    failed = data.get("failed")
    if isinstance(passed, int) and isinstance(failed, int):
        return passed, failed
    p = f = 0
    for check in data.get("checks", []) or []:
        if not isinstance(check, dict):
            continue
        status = str(check.get("status", "")).upper()
        if status == "PASS":
            p += 1
        elif status == "FAIL":
            f += 1
    return p, f


def _compliance_for_account(jobs_newest_first: list[Any], provider: str, wanted_ref: str) -> dict[str, Any]:
    """Aggregate stored CIS pass-rate for the account (newest run per provider).

    Only blocks whose normalized account matches ``wanted_ref`` are counted; a
    block with no resolvable account id is admitted only when its provider equals
    the requested account's provider (the view is provider-scoped anyway), so a
    different account's run can never leak into this account's pass-rate. Honest
    empty (``pass_rate: null``) when no benchmark run exists for the account.
    """
    from agent_bom.finding_scope import normalize_account_ref

    benchmarks: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_passed = total_failed = 0

    for job in jobs_newest_first:
        result = cast(dict[str, Any], getattr(job, "result", None) or {})
        for prov, keys in _CIS_SECTIONS:
            if provider and prov != provider:
                continue
            data: dict[str, Any] | None = None
            for key in keys:
                candidate = result.get(key)
                if isinstance(candidate, dict) and candidate:
                    data = candidate
                    break
            if data is None:
                continue
            block_provider = str(data.get("provider") or data.get("cloud_provider") or prov).strip().lower() or prov
            account_id = _cis_block_account_id(data)
            block_ref = normalize_account_ref(block_provider, account_id) if account_id else ""
            if block_ref:
                if block_ref.lower() != wanted_ref:
                    continue
            elif not provider or block_provider != provider:
                # No account id and no confident provider match — skip to stay honest.
                continue
            marker = f"{block_provider}:{block_ref or account_id or 'provider-scope'}"
            if marker in seen:
                continue  # newest run already recorded for this provider/account
            seen.add(marker)
            passed, failed = _cis_counts(data)
            evaluated = passed + failed
            total_passed += passed
            total_failed += failed
            benchmarks.append(
                {
                    "provider": block_provider,
                    "benchmark": str(data.get("benchmark") or "CIS"),
                    "passed": passed,
                    "failed": failed,
                    "evaluated": evaluated,
                    "pass_rate": round(passed / evaluated * 100, 1) if evaluated else None,
                }
            )

    evaluated = total_passed + total_failed
    return {
        "evaluated": evaluated,
        "passed": total_passed,
        "failed": total_failed,
        "pass_rate": round(total_passed / evaluated * 100, 1) if evaluated else None,
        "benchmarks": benchmarks,
    }
