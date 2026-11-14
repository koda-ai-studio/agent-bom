"""Steps 6–9: integrations, SIEM, exit codes."""

from __future__ import annotations

import logging
from typing import Any

from agent_bom.cli._common import SEVERITY_ORDER
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._stderr import stderr_notice
from agent_bom.evidence.cloud_posture import cloud_posture
from agent_bom.evidence.malicious_basis import malicious_label
from agent_bom.evidence.scan_run import NOTHING_TO_SCAN, ScanOutcome, effective_scan_run
from agent_bom.output import to_json


def run_integrations(
    ctx: ScanContext,
    *,
    quiet: bool,
    jira_url: Any,
    jira_user: Any,
    jira_token: Any,
    jira_project: Any,
    slack_webhook: Any,
    jira_discover: bool,
    servicenow_flag: bool,
    servicenow_instance: Any,
    servicenow_token: Any,
    slack_discover: bool,
    slack_bot_token: Any,
    vanta_token: Any,
    drata_token: Any,
    siem_type: Any,
    siem_url: Any,
    siem_token: Any,
    siem_index: Any,
    siem_format: str,
    clickhouse_url: Any,
    policy: Any = None,
    **kwargs: Any,
) -> None:
    """Step 8: enterprise integrations (Slack, Jira, Vanta, Drata, SIEM, ClickHouse)."""
    con = ctx.con
    blast_radii = ctx.blast_radii

    # Step 7b: Policy evaluation
    if policy and (blast_radii or getattr(ctx.report, "iac_findings_data", None)):
        from agent_bom.policy import evaluate_policy, load_policy

        try:
            policy_data = load_policy(policy)
            from agent_bom.output import print_policy_results

            policy_result = evaluate_policy(policy_data, blast_radii, report=ctx.report)
            print_policy_results(policy_result)
            ctx.policy_passed = ctx.policy_passed and bool(policy_result["passed"])

            jira_viol = policy_result.get("jira_violations", [])
            if jira_viol and jira_url and jira_token and jira_project:
                from agent_bom.policy import fire_policy_jira_actions

                n = fire_policy_jira_actions(
                    policy_result=policy_result,
                    jira_url=jira_url,
                    email=jira_user or "",
                    api_token=jira_token,
                    project_key=jira_project,
                )
                if n:
                    con.print(f"  [green]✓[/green] Policy: created {n} Jira ticket(s) for policy violations")
            elif jira_viol and not (jira_url and jira_token and jira_project):
                con.print(
                    f"  [yellow]⚠[/yellow]  Policy: {len(jira_viol)} rule(s) have action='jira' but "
                    "--jira-url/--jira-token/--jira-project are not set"
                )
        except (FileNotFoundError, ValueError) as e:
            import sys

            con.print(f"\n  [red]Policy error: {e}[/red]")
            sys.exit(1)

    # Step 7c: ClickHouse analytics (optional, post-scan)
    if clickhouse_url and blast_radii:
        try:
            import uuid as _uuid_ch

            from agent_bom.analytics_contract import build_scan_analytics_payload
            from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

            _ch_store = ClickHouseAnalyticsStore(url=clickhouse_url)
            _scan_id = str(_uuid_ch.uuid4())
            # CLI runs against a shared ClickHouse are tagged with the
            # operator's tenant so reads stay segregated. Resolution path
            # lives in agent_bom.cli._tenant — the only sanctioned reader
            # of AGENT_BOM_TENANT_ID from CLI code (#1964).
            from agent_bom.cli._tenant import resolve_cli_tenant_id

            _ch_tenant_id = resolve_cli_tenant_id()
            if ctx.report:
                analytics = build_scan_analytics_payload(ctx.report, scan_id=_scan_id, source="cli")
                for agent_name, findings in analytics.agent_findings.items():
                    _ch_store.record_scan(analytics.scan_id, agent_name, findings, tenant_id=_ch_tenant_id)
                _ch_store.record_scan_metadata(analytics.scan_metadata, tenant_id=_ch_tenant_id)
                for agent_name, snapshot in analytics.posture_snapshots.items():
                    _ch_store.record_posture(agent_name, snapshot, tenant_id=_ch_tenant_id)
                for fleet_snapshot in analytics.fleet_snapshots:
                    fleet_snapshot.setdefault("tenant_id", _ch_tenant_id)
                    _ch_store.record_fleet_snapshot(fleet_snapshot)
                for control in analytics.compliance_controls:
                    _ch_store.record_compliance_control(control, tenant_id=_ch_tenant_id)
                _ch_store.record_cis_benchmark_checks(analytics.cis_benchmark_checks, tenant_id=_ch_tenant_id)
            if not quiet:
                _finding_count = sum(len(findings) for findings in analytics.agent_findings.values()) if ctx.report else 0
                con.print(f"  [green]✓[/green] Analytics: {_finding_count} finding(s) recorded to ClickHouse")
        except Exception as _ch_exc:
            if not quiet:
                con.print(f"  [yellow]⚠[/yellow] ClickHouse analytics: {_ch_exc}")

    # Step 8: Enterprise integrations (optional, post-scan)
    if blast_radii and (slack_webhook or jira_url or vanta_token or drata_token):
        import asyncio as _asyncio_int

        findings = []
        for br in blast_radii:
            findings.append(
                {
                    "vulnerability_id": br.vulnerability.id,
                    "severity": br.vulnerability.severity.value.lower(),
                    "package": f"{br.package.name}@{br.package.version}",
                    "risk_score": br.risk_score,
                    "affected_agents": [a.name for a in br.affected_agents] if br.affected_agents else [],
                    "affected_servers": [s.name for s in br.affected_servers] if br.affected_servers else [],
                    "exposed_credentials": list(br.exposed_credentials) if br.exposed_credentials else [],
                    "fixed_version": br.vulnerability.fixed_version,
                    "owasp_tags": list(br.owasp_tags) if br.owasp_tags else [],
                    "owasp_mcp_tags": list(br.owasp_mcp_tags) if br.owasp_mcp_tags else [],
                    "atlas_tags": list(br.atlas_tags) if br.atlas_tags else [],
                    "nist_ai_rmf_tags": list(br.nist_ai_rmf_tags) if br.nist_ai_rmf_tags else [],
                }
            )

        if slack_webhook and findings:
            try:
                from agent_bom.integrations.slack import build_summary_message, send_slack_alert, send_slack_payload

                async def _send_slack():
                    delivered = 0
                    failed = 0
                    for f in findings[:10]:
                        if await send_slack_alert(slack_webhook, f):
                            delivered += 1
                        else:
                            failed += 1
                    if len(findings) > 1:
                        summary = build_summary_message(findings)
                        if await send_slack_payload(slack_webhook, summary):
                            delivered += 1
                        else:
                            failed += 1
                    return delivered, failed

                delivered, failed = _asyncio_int.run(_send_slack())
                attempted = min(len(findings), 10) + (1 if len(findings) > 1 else 0)
                if delivered == attempted:
                    con.print(f"  [green]✓[/green] Slack: delivered {delivered} message(s)")
                elif delivered:
                    con.print(f"  [yellow]⚠[/yellow] Slack: delivered {delivered}/{attempted} message(s); {failed} failed")
                else:
                    con.print(f"  [yellow]⚠[/yellow] Slack: delivered 0/{attempted} message(s); check webhook reachability and URL policy")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Slack alert failed: {exc}")

        if jira_url and jira_token and jira_project and findings:
            try:
                from agent_bom.integrations.jira import create_jira_ticket

                async def _create_jira():
                    created = 0
                    for f in findings[:20]:
                        await create_jira_ticket(jira_url, jira_user or "", jira_token, jira_project, f)
                        created += 1
                    return created

                jira_count = _asyncio_int.run(_create_jira())
                con.print(f"  [green]✓[/green] Jira: created {jira_count} ticket(s)")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Jira ticket creation failed: {exc}")

        if vanta_token and findings:
            try:
                from agent_bom.integrations.vanta import upload_evidence

                _asyncio_int.run(upload_evidence(vanta_token, findings))  # type: ignore[arg-type]
                con.print("  [green]✓[/green] Vanta: evidence uploaded")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Vanta upload failed: {exc}")

        if drata_token and findings:
            try:
                from agent_bom.integrations.drata import upload_evidence as upload_evidence_drata

                _asyncio_int.run(upload_evidence_drata(drata_token, findings))  # type: ignore[arg-type]
                con.print("  [green]✓[/green] Drata: evidence uploaded")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Drata upload failed: {exc}")

    # SIEM push
    if siem_type and siem_url and blast_radii:
        try:
            from agent_bom.siem import SIEMConfig, create_connector, format_event

            siem_config = SIEMConfig(
                name=siem_type,
                url=siem_url,
                token=siem_token or "",
                index=siem_index or "agent-bom-alerts",
                event_format=siem_format,
            )
            connector = create_connector(siem_type, siem_config)

            events: list[dict] = []
            for br in blast_radii:
                raw = {
                    "type": "scan_alert",
                    "severity": br.vulnerability.severity.value,
                    "message": f"{br.vulnerability.id} in {br.package.name}@{br.package.version}",
                    "vulnerability_id": br.vulnerability.id,
                    "package": br.package.name,
                    "version": br.package.version,
                    "ecosystem": br.package.ecosystem,
                    "is_kev": br.vulnerability.is_kev,
                    "affected_agents": [a.name for a in br.affected_agents],
                    "exposed_credentials": br.exposed_credentials,
                    "atlas_tags": getattr(br, "atlas_tags", []),
                    "attack_tags": getattr(br, "attack_tags", []),
                    "owasp_tags": getattr(br, "owasp_tags", []),
                }
                events.append(format_event(raw, siem_format))

            sent = connector.send_batch(events)
            con.print(f"  [green]✓[/green] SIEM ({siem_type}): pushed {sent}/{len(events)} event(s)")
        except Exception as exc:
            con.print(f"  [yellow]⚠[/yellow] SIEM push failed: {exc}")
    elif siem_type and not siem_url:
        con.print(f"  [yellow]⚠[/yellow] --siem {siem_type} set but --siem-url is required")


# Severities that carry no usable rank for a policy gate: UNKNOWN means the
# finding has not been enriched yet, NONE means a missing/zeroed score. Both
# compare below every selectable --fail-on-severity threshold, so a naive
# rank comparison lets them slip past an active gate (fail-open). Treat them as
# tripping any active gate instead (fail-closed) — a CVE whose severity has not
# resolved must not silently pass CI.
_FAIL_CLOSED_SEVERITIES = frozenset({"unknown", "none"})

# Published home of the full CLI exit-code / HTTP-status contract.
EXIT_CODE_CONTRACT_URL = "https://koda-ai-studio.github.io/agent-bom/reference/exit-codes/"


def _fail_gate_meets(sev: str, threshold: int) -> bool:
    """Return True if a finding's severity should trip an active fail gate.

    Fail-closed for UNKNOWN/NONE severities; otherwise compare by rank.
    """
    if sev in _FAIL_CLOSED_SEVERITIES:
        return True
    return SEVERITY_ORDER.get(sev, 0) >= threshold


def _local_db_kev_is_fresh(report: Any) -> bool:
    """Whether the scan's local vulnerability DB carried current KEV rows.

    Matching against the local DB already joins ``kev_entries``; when that DB
    is within its freshness SLO it is KEV evidence even though no catalog was
    fetched in this process.
    """
    freshness = getattr(report, "vuln_data_freshness", None) if report is not None else None
    if not isinstance(freshness, dict) or freshness.get("stale") is not False:
        return False
    return "KEV" in {str(source).upper() for source in freshness.get("sources") or []}


def _gate_findings(report: Any) -> list:
    """Non-CVE findings the severity gates read.

    An errored control is missing evidence, not a finding: it reaches the exit
    code through the incomplete-scan gate, and real failures lead the reason.
    """
    from agent_bom.finding import FindingType

    excluded = {FindingType.CVE, FindingType.CIS_ERROR, FindingType.CLOUD_BEST_PRACTICE_ERROR}
    return [finding for finding in report.to_findings() if finding.finding_type not in excluded]


def _execution_outcome(report: Any) -> Any:
    """Canonical outcome, partial as well when cloud controls went unevaluated."""
    outcome = effective_scan_run(report).outcome
    return ScanOutcome.PARTIAL if outcome is ScanOutcome.COMPLETE and cloud_posture(report).partial else outcome


def _push_report(ctx: ScanContext, report: Any, push_url: str, push_api_key: str | None, *, quiet: bool) -> bool:
    """Send the report to the control plane; automation must see an undelivered push."""
    from agent_bom.push import PushAuthError, PushTooLargeError, normalize_scan_push_url, push_results
    from agent_bom.security import sanitize_error, sanitize_url

    con = ctx.con
    endpoint = sanitize_url(push_url)
    reason = ""
    try:
        resolved_push_url = normalize_scan_push_url(push_url)
        endpoint = sanitize_url(resolved_push_url)
        report_data = {**to_json(report), **({"target_scope": ctx.target_scope} if ctx.target_scope else {})}
        if push_results(resolved_push_url, report_data, api_key=push_api_key):
            if not quiet:
                con.print(f"\n  [green]Results pushed to {endpoint}[/green]")
            return True
    except (PushTooLargeError, PushAuthError) as exc:
        # Authored numbers and advice only; the generic 200-character error cap would cut the split advice.
        reason = f": {exc}"
    except Exception as exc:  # noqa: BLE001
        reason = f": {sanitize_error(exc)}"
    message = f"results were not delivered to {endpoint}{reason}; the local report is unaffected"
    if quiet:
        stderr_notice(message)
    else:
        con.print("\n  [red bold]Exiting with code 1: [/red bold]", end="")
        con.print(message, markup=False, highlight=False)
    return False


def _record_exit_reason(ctx: Any, message: str) -> None:
    # Callers may pass a partial stand-in context; recording a reason must never break the exit verdict.
    reasons = getattr(ctx, "exit_reasons", None)
    if not isinstance(reasons, list):
        reasons = []
        ctx.exit_reasons = reasons
    reasons.append(message)


def _exit_reason(ctx: ScanContext, quiet: bool, message: str) -> None:
    """Record why the scan exits non-zero; print it now unless -q, whose summary prints it instead."""
    _record_exit_reason(ctx, message)
    if not quiet:
        ctx.con.print("\n  [red]Exiting with code 1: [/red]", end="")
        ctx.con.print(message, style="red", markup=False, highlight=False)


def _malicious_finding_reason(finding: Any) -> str:
    asset_kind = "package" if finding.asset.asset_type == "package" else finding.asset.asset_type.replace("_", " ")
    reason = finding.malicious_reason or f"known malicious {asset_kind}"
    return f"{malicious_label(finding.malicious_reason)} {asset_kind} {finding.asset.name} ({reason})"


def _malicious_package_reason(pkg: Any) -> str:
    reason = getattr(pkg, "malicious_reason", None) or "known malicious package"
    return f"{malicious_label(getattr(pkg, 'malicious_reason', None))} package {pkg.name} ({reason})"


def compute_exit_code(
    ctx: ScanContext,
    *,
    fail_on_severity: Any,
    warn_on_severity: Any,
    fail_on_kev: bool,
    fail_if_ai_risk: bool,
    push_url: Any,
    push_api_key: Any,
    quiet: bool,
    fail_on_malicious: bool = False,
    **kwargs: Any,
) -> int:
    """Step 9: compute final exit code based on policy flags."""
    con = ctx.con
    blast_radii = ctx.blast_radii
    report = ctx.report

    exit_code = 0

    # Filter blast radii to exclude VEX-suppressed vulnerabilities
    from agent_bom.vex import is_vex_suppressed as _is_vex_suppressed

    _active_blast_radii = [br for br in blast_radii if not br.suppressed and not _is_vex_suppressed(br.vulnerability)]

    # Delta mode: further restrict active findings to new-only
    if ctx.delta_result is not None:
        _new_keys = {(d.get("vulnerability_id", "").upper(), d.get("package", "")) for d in ctx.delta_result.new_items}
        _active_blast_radii = [
            br for br in _active_blast_radii if (br.vulnerability.id.upper(), f"{br.package.name}@{br.package.version}") in _new_keys
        ]

    if fail_on_severity and _active_blast_radii:
        fail_threshold = str(fail_on_severity).lower()
        threshold = SEVERITY_ORDER.get(fail_threshold, 0)
        for br in _active_blast_radii:
            sev = br.vulnerability.severity.value.lower()
            if _fail_gate_meets(sev, threshold):
                _exit_reason(ctx, quiet, f"found {sev} vulnerability ({br.vulnerability.id})")
                exit_code = 1
                break

    # IaC findings also respect --fail-on-severity
    if fail_on_severity and exit_code == 0 and report and report.iac_findings_data:
        fail_threshold = str(fail_on_severity).lower()
        threshold = SEVERITY_ORDER.get(fail_threshold, 0)
        for f in report.iac_findings_data.get("findings", []):
            sev = (f.get("severity") or "medium").lower()
            if _fail_gate_meets(sev, threshold):
                _exit_reason(ctx, quiet, f"IaC {sev} misconfiguration ({f.get('rule_id', '?')} in {f.get('file_path', '?')})")
                exit_code = 1
                break

    # Unified non-CVE findings (for example MCP_BLOCKLIST) also respect
    # --fail-on-severity. CVEs are handled above through blast_radii so VEX and
    # delta filtering keep their existing semantics.
    unified_findings = _gate_findings(report) if report else []

    if fail_on_severity and exit_code == 0 and unified_findings:
        fail_threshold = str(fail_on_severity).lower()
        threshold = SEVERITY_ORDER.get(fail_threshold, 0)
        for finding in unified_findings:
            sev = str(finding.severity or "low").lower()
            if _fail_gate_meets(sev, threshold):
                if getattr(finding, "is_malicious", False):
                    _exit_reason(ctx, quiet, _malicious_finding_reason(finding))
                else:
                    _exit_reason(ctx, quiet, f"found {sev} finding ({finding.finding_type.value})")
                exit_code = 1
                break

    # AI skill findings participate in CI only after the operator explicitly
    # selects deterministic execution and --ai-gate-findings. The immutable
    # deterministic_passed value remains in the artifact for audit/replay.
    skill_audit = ctx.skill_audit_data if isinstance(ctx.skill_audit_data, dict) else {}
    if skill_audit.get("ai_gate_enabled") is True and skill_audit.get("passed") is False:
        _exit_reason(ctx, quiet, "deterministic-mode AI skill finding gate failed")
        exit_code = 1

    # Two-tier: warn-on threshold (exit 0 with banner)
    if warn_on_severity and _active_blast_radii and exit_code == 0:
        warn_threshold = SEVERITY_ORDER.get(warn_on_severity.lower(), 0)
        warn_matches = [
            br for br in _active_blast_radii if SEVERITY_ORDER.get(br.vulnerability.severity.value.lower(), 0) >= warn_threshold
        ]
        if warn_matches:
            if not quiet:
                con.print(
                    f"\n  [yellow]⚠[/yellow]  {len(warn_matches)} finding(s) at or above "
                    f"{warn_on_severity.upper()} severity (--warn-on threshold). "
                    f"Upgrade to --fail-on-severity to enforce."
                )

    if warn_on_severity and unified_findings and exit_code == 0:
        warn_threshold = SEVERITY_ORDER.get(warn_on_severity.lower(), 0)
        warn_matches = [finding for finding in unified_findings if SEVERITY_ORDER.get(str(finding.severity).lower(), 0) >= warn_threshold]
        if warn_matches and not quiet:
            con.print(
                f"\n  [yellow]⚠[/yellow]  {len(warn_matches)} non-CVE finding(s) at or above "
                f"{str(warn_on_severity).upper()} severity (--warn-on threshold). "
                f"Upgrade to --fail-on-severity to enforce."
            )

    # A flagged package is a fail-closed BLOCK regardless of the opt-in
    # --fail-on-malicious flag, mirroring `check`, which always exits 1 on a
    # malicious or suspected-malicious verdict. A default scan silently exiting 0
    # on a typosquat / dependency-confusion / known-malicious advisory would let
    # it install.
    if exit_code == 0:
        for br in _active_blast_radii:
            if getattr(br.package, "is_malicious", False):
                _exit_reason(ctx, quiet, _malicious_package_reason(br.package))
                exit_code = 1
                break
        if exit_code == 0 and report:
            for finding in report.to_findings():
                if getattr(finding, "is_malicious", False):
                    _exit_reason(ctx, quiet, _malicious_finding_reason(finding))
                    exit_code = 1
                    break
            if exit_code == 0:
                for agent in report.agents:
                    for server in agent.mcp_servers:
                        for pkg in server.packages:
                            if getattr(pkg, "is_malicious", False):
                                _exit_reason(ctx, quiet, _malicious_package_reason(pkg))
                                exit_code = 1
                                break
                        if exit_code:
                            break
                    if exit_code:
                        break

    if fail_on_kev and _active_blast_radii:
        kev_findings = [br for br in _active_blast_radii if br.vulnerability.is_kev]
        if kev_findings:
            _exit_reason(ctx, quiet, f"{len(kev_findings)} CISA KEV finding(s) found (use --enrich if not already)")
            exit_code = 1
        else:
            sources = ctx.enrichment_posture.get("sources", []) if isinstance(ctx.enrichment_posture, dict) else []
            kev_source = next(
                (source for source in sources if isinstance(source, dict) and source.get("source") == "cisa_kev"),
                None,
            )
            kev_status = str(kev_source.get("status") if kev_source else "unknown")
            if kev_status != "ok" and not _local_db_kev_is_fresh(report):
                message = (
                    f"CISA KEV evidence is unavailable or stale (catalog status: {kev_status}); "
                    "--fail-on-kev cannot prove a clean result. Run online (the KEV catalog is fetched "
                    "automatically), or refresh local data with `agent-bom db update`, or pass --enrich."
                )
                _exit_reason(ctx, quiet, message)
                exit_code = 1

    if fail_if_ai_risk and _active_blast_radii:
        ai_findings = [br for br in _active_blast_radii if br.ai_risk_context and br.exposed_credentials]
        if ai_findings:
            _exit_reason(ctx, quiet, f"{len(ai_findings)} AI framework package(s) with vulnerabilities and exposed credentials")
            exit_code = 1

    if not ctx.policy_passed:
        _record_exit_reason(ctx, "policy check failed (the policy results list the failing rules)")
        exit_code = 1

    # A requested cloud provider that hard-failed discovery or benchmarking
    # (missing SDK / absent / invalid credentials) must surface as a non-zero
    # exit so a silent pass in CI is impossible. A genuinely empty-but-successful
    # scan records no failure and still exits 0.
    if ctx.cloud_provider_failures:
        providers = ", ".join(sorted({str(f.get("provider", "?")) for f in ctx.cloud_provider_failures}))
        _exit_reason(ctx, quiet, f"cloud provider discovery failed for {providers} (collector unavailable or incomplete)")
        exit_code = 1

    # Evidence quality is an automation boundary, independent of finding gates.
    # A requested collector that degraded or failed must never produce a clean
    # process exit even when the partial artifact contains zero findings.
    if report is not None:
        scan_outcome = _execution_outcome(report)
        nothing_scanned = next((issue for issue in effective_scan_run(report).issues if issue.code == NOTHING_TO_SCAN), None)
        if nothing_scanned is not None:
            # A repository without dependencies is normal in CI. The report withholds the grade instead of failing the job.
            stderr_notice(nothing_scanned.message, level=logging.WARNING)
        elif scan_outcome is not ScanOutcome.COMPLETE:
            if not ctx.cloud_provider_failures:
                _exit_reason(ctx, quiet, f"scan execution was {scan_outcome.value}; inspect scan_run.scopes and scan_run.issues")
            exit_code = 1

    # Every branch above prints the specific reason it tripped. What none of
    # them say is that a non-zero exit is the scanner working as designed — to a
    # first-time reader a red "Exiting with code 1" is indistinguishable from a
    # crash. State the contract once, plainly, without changing the code itself.
    if exit_code == 1 and not quiet:
        con.print(
            "\n  [dim]Exit code 1 is a scan verdict, not a scanner error — the reason is above and the "
            f"report records findings and coverage limits.\n  Exit-code contract: {EXIT_CODE_CONTRACT_URL}[/dim]"
        )

    if push_url and report and not _push_report(ctx, report, push_url, push_api_key, quiet=quiet):
        exit_code = exit_code or 1

    ctx.exit_code = exit_code
    return exit_code
