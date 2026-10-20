"""Cloud scanning REST routes — estate inventory + CIS benchmark over HTTP.

Cloud discovery has long been reachable from the CLI (``agent-bom cloud …``) and
over MCP (``cloud_inventory`` / ``cis_benchmark`` tools), but not over REST. That
left API-only / SaaS consumers unable to reach cloud scanning at all. These
endpoints close the surface-parity gap by calling the **same** cloud inventory and
CIS benchmark functions the CLI and MCP already use, returning a deterministic
result shape that matches them field-for-field.

Endpoints:
    GET /v1/cloud/{provider}/inventory       estate asset inventory summary
    GET /v1/cloud/{provider}/cis-benchmark   CIS Foundations benchmark report

For inventory, ``provider`` is one of ``aws`` | ``azure`` | ``gcp`` | ``snowflake``;
``all`` is also accepted (estate-wide fan-out). Every endpoint enforces the same tenant + role
gate the sibling routes use: ``require_request_tenant_id`` plus the ``scan``
permission ({admin, analyst}) via the shared RBAC dependency, so there is no
unauthenticated cloud scan and an under-privileged role is rejected with 403.

Responses are additive: where the underlying scan carries a read-only discovery
envelope (``permissions_used`` / discovery scope), it is surfaced under
``audit_metadata`` so auditors can verify the read-only scope used."""

from __future__ import annotations

import re
from importlib import import_module
from typing import Any, Literal, cast

import anyio
import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.cloud_inventory_read import _INVENTORY_PROVIDERS, _build_inventory_payload
from agent_bom.api.cloud_response_helpers import _cloud_cis_timeout_seconds, _cloud_inventory_timeout_seconds, _logger, _tenant
from agent_bom.api.cloud_scan_results import (
    _run_cis_benchmark,
    _run_provider_side_scan_sync,
    _runtime_cohort_graph,
    _runtime_cohort_response,
    _side_scan_result_summary,
)
from agent_bom.api.cloud_summary_read import _account_findings_href, _compliance_for_account, _split_account_ref
from agent_bom.api.correlation_cohort_ingest import (
    CorrelationCohortIngestError,
    cohort_evidence_created_at,
    commit_correlation_cohort_child,
    prior_or_conflict,
    validate_correlation_cohort_child,
)
from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    IdempotencyReservationHeartbeat,
    idempotency_owner_token,
    idempotency_request_fingerprint,
    idempotency_reservation_lease_seconds,
)
from agent_bom.api.models import RuntimeEvidenceIngestRequest, ScanJob, SideScanTriggerRequest
from agent_bom.api.read_models import documented
from agent_bom.api.read_models import runtime_estate_a as rt
from agent_bom.api.stores import _get_graph_store, _get_idempotency_store, _get_store
from agent_bom.backpressure import (
    BackpressureRejectedError,
    ProviderExecutionCapacityError,
    ProviderExecutionTimeoutError,
    adaptive_backpressure,
    run_provider_call,
)
from agent_bom.cloud.ambient_credentials import PROFILE_REJECTED_NOTE, ambient_cis_enabled, configured_aws_profile, disabled_payload
from agent_bom.cloud.runtime_workload_evidence import SourceAuthenticationError, get_runtime_source_registry, ingest_runtime_signals
from agent_bom.cloud.runtime_workload_evidence_store import get_runtime_workload_evidence_store
from agent_bom.rbac import require_authenticated_permission
from agent_bom.redaction.log_values import sanitize_log_value
from agent_bom.security import sanitize_log_label, sanitize_text

router = APIRouter(tags=["cloud"])


_SCAN_DEP = require_authenticated_permission("scan")


_CIS_DEP = require_authenticated_permission("cloud_ambient")


_READ_DEP = require_authenticated_permission("read")


_ACCOUNT_SUMMARY_MAX_ROWS = 50_000


_IDENTITY_ASSET_TYPES = frozenset({"user", "service_account", "identity", "iam_user", "principal", "machine_identity", "nhi"})


_ROLE_ASSET_TYPES = frozenset({"role", "iam_role", "cloud_role"})


_CIS_PROVIDERS = ("aws", "azure", "gcp", "snowflake", "databricks")


_REGION_RE = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-\d{1,2}")


_PROFILE_RE = re.compile(r"[a-zA-Z0-9._-]{1,100}")


@router.get("/cloud/{provider}/inventory", **documented(rt.CloudInventorySummaryResponse))
async def cloud_inventory(
    request: Request,
    provider: str,
    region: str = Query("", description="Optional region scope (AWS only, e.g. us-east-1)."),
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Estate-wide cloud asset inventory summary for a provider (or ``all``).

    Calls the same ``discover_inventory`` / ``discover`` functions the CLI and MCP
    ``cloud_inventory`` tool use and reduces each provider payload to the identical
    non-secret count shape. ``aws`` | ``azure`` | ``gcp`` | ``snowflake`` (and
    ``all``) are supported; Snowflake's AI-resource discovery is projected onto the
    same summary fields (see ``_snowflake_inventory``). Each provider self-gates on
    its own ``AGENT_BOM_*_INVENTORY`` env flag + credentials; a disabled provider
    returns a clear ``status`` and contributes zero nodes.
    """
    tenant_id = _tenant(request)
    requested = provider.strip().lower()
    if requested == "all":
        selected = list(_INVENTORY_PROVIDERS)
    elif requested in _INVENTORY_PROVIDERS:
        selected = [requested]
    else:
        raise HTTPException(
            status_code=404,
            detail=f"Unsupported provider '{provider}'. Use one of: {', '.join((*_INVENTORY_PROVIDERS, 'all'))}.",
        )

    scoped_region = region.strip() or None
    if scoped_region and not _REGION_RE.fullmatch(scoped_region):
        raise HTTPException(status_code=400, detail=f"Invalid region format: {region}")

    try:
        # Provider discovery runs synchronous SDK/network calls; offload the whole
        # scan to a worker thread under backpressure so a live inventory can never
        # stall the event loop (a burst sheds with a 429 instead).
        async with adaptive_backpressure("cloud_inventory"):
            try:
                return await run_provider_call(
                    _build_inventory_payload,
                    tenant_id,
                    selected,
                    scoped_region,
                    timeout_seconds=_cloud_inventory_timeout_seconds(),
                )
            except ProviderExecutionTimeoutError:
                _logger.warning("Cloud inventory timed out for %s", sanitize_log_value(requested))
                return {
                    "error": "Provider inventory timed out before completing.",
                    "provider": requested,
                    "tenant_id": tenant_id,
                    "status": "unavailable",
                    "timed_out": True,
                    "audit_metadata": {
                        "read_only": True,
                        "writes_performed": False,
                        "provider": requested,
                        "note": "No cloud resource was mutated; retry with a scoped provider connection.",
                    },
                }
            except ProviderExecutionCapacityError as exc:
                raise HTTPException(
                    status_code=429,
                    detail="Cloud provider execution capacity is exhausted; retry later.",
                    headers={"Retry-After": "1"},
                ) from exc
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Full diagnostics go to the server log only; the client gets a generic
        # message so no exception/stack detail is exposed over REST.
        _logger.error("Cloud inventory failed")
        raise HTTPException(status_code=500, detail="Cloud inventory failed; see server logs.") from exc


@router.get("/cloud/{provider}/cis-benchmark", **documented(rt.CloudCisBenchmarkResponse))
async def cloud_cis_benchmark(
    request: Request,
    provider: str,
    checks: str = Query("", description="Optional comma-separated benchmark check ids to scope the run."),
    region: str = Query("", description="Optional AWS region (e.g. us-east-1)."),
    profile: str = Query("", description="Optional AWS profile name."),
    subscription_id: str = Query("", description="Optional Azure subscription id."),
    project_id: str = Query("", description="Optional GCP project id."),
    _role: Any = _CIS_DEP,
) -> dict[str, Any]:
    """Run provider posture checks; Databricks uses vendor guidance, not CIS.

    Calls the same provider ``run_benchmark`` functions the CLI and MCP
    ``cis_benchmark`` tool use and returns the report's canonical ``to_dict()``
    shape unchanged, so REST / CLI / MCP report the same checks and counts.
    """
    tenant_id = _tenant(request)
    requested = provider.strip().lower()
    if requested not in _CIS_PROVIDERS:
        raise HTTPException(
            status_code=404,
            detail=f"Unsupported provider '{provider}'. Use one of: {', '.join(_CIS_PROVIDERS)}.",
        )

    check_list = [c.strip() for c in checks.split(",") if c.strip()] or None
    region_arg = region.strip() or None
    if profile.strip():
        # Choosing which host credential to spend is operator configuration.
        # Accepting it from the request would let any caller pivot across every
        # profile mounted on the control plane.
        raise HTTPException(status_code=400, detail=PROFILE_REJECTED_NOTE)
    profile_arg = configured_aws_profile()
    if region_arg and not _REGION_RE.fullmatch(region_arg):
        raise HTTPException(status_code=400, detail=f"Invalid AWS region format: {region}")
    if profile_arg and not _PROFILE_RE.fullmatch(profile_arg):
        raise HTTPException(
            status_code=400,
            detail="Invalid AWS profile name. Use alphanumeric, dot, dash, underscore (max 100 chars).",
        )

    if not ambient_cis_enabled():
        # Off by default: this evaluates with whatever credentials the
        # control-plane process itself holds, so a stock install must never
        # spend them on request.
        return {**disabled_payload(requested), "tenant_id": tenant_id}

    try:
        # A full CIS benchmark runs synchronous provider SDK/network evaluation;
        # offload it to a worker thread under backpressure so it never stalls the
        # event loop (a burst sheds with a 429 instead). The timeout abandons the
        # worker if a provider SDK is stuck in credential/metadata retries; the
        # request must not hold an API slot indefinitely.
        async with adaptive_backpressure("cloud_cis"):
            try:
                return await run_provider_call(
                    _run_cis_benchmark,
                    tenant_id,
                    requested,
                    check_list,
                    region_arg,
                    profile_arg,
                    subscription_id,
                    project_id,
                    timeout_seconds=_cloud_cis_timeout_seconds(),
                )
            except ProviderExecutionTimeoutError:
                _logger.warning("Cloud CIS benchmark timed out for %s", sanitize_log_value(requested))
                return {
                    "error": "Provider benchmark timed out before completing.",
                    "provider": requested,
                    "tenant_id": tenant_id,
                    "status": "unavailable",
                    "timed_out": True,
                    "audit_metadata": {
                        "read_only": True,
                        "writes_performed": False,
                        "provider": requested,
                        "note": "No cloud resource was mutated; retry with a scoped provider connection.",
                    },
                }
            except ProviderExecutionCapacityError as exc:
                raise HTTPException(
                    status_code=429,
                    detail="Cloud provider execution capacity is exhausted; retry later.",
                    headers={"Retry-After": "1"},
                ) from exc
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Full diagnostics to the server log only; client gets a generic message.
        _logger.error("Cloud CIS benchmark failed")
        raise HTTPException(status_code=500, detail="Cloud CIS benchmark failed; see server logs.") from exc


def _build_account_summary(tenant_id: str, raw_account_ref: str) -> dict[str, Any]:
    """Compose the per-account drill payload from stored evidence (sync body).

    Runs in a worker thread (see the route). Reuses the #3946 domain rollup
    buckets, the #3946 scope filters, and the shared scan-store helpers so no
    counting logic is re-implemented here.
    """
    from agent_bom.api.finding_scope_filters import _canonical_scope_filters, _finding_identity, _row_matches_scope
    from agent_bom.api.routes.overview import (
        _ALL_SEVERITY_KEYS,
        _COVERAGE_DOMAINS,
        _COVERAGE_LABELS,
        _bucket,
        _empty_severity,
        _row_domain,
    )
    from agent_bom.api.scan_finding_read import _bulk_ingested_findings_for_tenant, _completed_jobs_for_tenant

    canonical_ref, provider, account = _split_account_ref(raw_account_ref)

    lanes: dict[str, dict[str, int]] = {dom: _empty_severity() for dom in _COVERAGE_DOMAINS}
    counts: dict[str, int] = {dom: 0 for dom in _COVERAGE_DOMAINS}
    total_severity = _empty_severity()
    regions: set[str] = set()
    environments: set[str] = set()
    asset_ids: set[str] = set()
    identity_ids: set[str] = set()
    role_ids: set[str] = set()
    processed = 0
    truncated = False

    jobs = _completed_jobs_for_tenant(tenant_id)
    jobs_newest_first = sorted(
        jobs,
        key=lambda job: (getattr(job, "completed_at", "") or "", getattr(job, "created_at", "") or "", job.job_id),
        reverse=True,
    )

    if canonical_ref:
        # Dedupe findings across re-scans (latest occurrence of each id wins),
        # exactly like the findings-list default view, then fold bulk-ingested
        # rows in under the same identity so a finding seen twice counts once.
        filters = _canonical_scope_filters(None, canonical_ref, None, None)
        deduped: dict[str, dict[str, Any]] = {}
        for job in sorted(
            jobs,
            key=lambda job: (getattr(job, "completed_at", "") or "", getattr(job, "created_at", "") or "", job.job_id),
        ):
            for row in cast(dict[str, Any], getattr(job, "result", None) or {}).get("findings", []) or []:
                if isinstance(row, dict):
                    deduped[_finding_identity(row)] = row
        for row in _bulk_ingested_findings_for_tenant(tenant_id):
            if isinstance(row, dict):
                deduped.setdefault(_finding_identity(row), row)

        for row in deduped.values():
            if not _row_matches_scope(row, filters):
                continue
            if processed >= _ACCOUNT_SUMMARY_MAX_ROWS:
                truncated = True
                break
            processed += 1
            dom = _row_domain(row)
            bucket = _bucket(str(row.get("severity") or ""), lanes[dom])
            lanes[dom][bucket] += 1
            counts[dom] += 1
            total_severity[bucket] += 1
            region = str(row.get("region") or "").strip()
            if region:
                regions.add(region)
            environment = str(row.get("environment") or "").strip()
            if environment:
                environments.add(environment)
            raw_asset = row.get("asset")
            asset: dict[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
            identifier = str(asset.get("identifier") or asset.get("name") or "").strip()
            asset_type = str(asset.get("asset_type") or "").strip().lower()
            if identifier:
                asset_ids.add(identifier)
                if asset_type in _IDENTITY_ASSET_TYPES:
                    identity_ids.add(identifier)
                if asset_type in _ROLE_ASSET_TYPES:
                    role_ids.add(identifier)

    compliance = (
        _compliance_for_account(jobs_newest_first, provider, canonical_ref)
        if canonical_ref
        else {"evaluated": 0, "passed": 0, "failed": 0, "pass_rate": None, "benchmarks": []}
    )
    compliance["href"] = _account_findings_href(canonical_ref, provider, domain="cspm")

    findings_total = sum(counts.values())
    domains = [
        {
            "domain": dom,
            "label": _COVERAGE_LABELS[dom],
            "count": counts[dom],
            "severity": {key: lanes[dom][key] for key in _ALL_SEVERITY_KEYS},
            "href": _account_findings_href(canonical_ref, provider, domain=dom),
        }
        for dom in _COVERAGE_DOMAINS
    ]

    return {
        "schema_version": "cloud.account.summary.v1",
        "tenant_id": tenant_id,
        "account_ref": canonical_ref,
        "provider": provider,
        "account": account,
        "regions": sorted(regions),
        "environments": sorted(environments),
        "findings_total": findings_total,
        "severity": {key: total_severity[key] for key in _ALL_SEVERITY_KEYS},
        "domains": domains,
        "compliance": compliance,
        "assets": {
            "count": len(asset_ids),
            "href": f"/inventory/assets?provider={provider}" if provider else "/inventory/assets",
            "note": "Distinct assets referenced by findings in this account.",
        },
        "identities": {
            "count": len(identity_ids),
            "roles": len(role_ids),
            "note": "Derived from finding assets; full IAM role/grant enumeration is a follow-up.",
        },
        "drill": {
            "findings_href": _account_findings_href(canonical_ref, provider),
            "graph_href": f"/graph?provider={provider}" if provider else "/graph",
        },
        "truncated": truncated,
        "empty": findings_total == 0 and compliance["evaluated"] == 0,
        "note": (
            "Read-only aggregation over already-ingested findings and stored CIS benchmark runs, "
            "scoped to this provider+account. No live provider scan is triggered."
        ),
    }


@router.get("/cloud/accounts/{account_ref}/summary", **documented(rt.CloudAccountSummaryResponse))
async def cloud_account_summary(
    request: Request,
    account_ref: str,
    _role: Any = _READ_DEP,
) -> dict[str, Any]:
    """Per-account, end-to-end posture drill for one cloud account (issue #3931).

    Returns findings by security domain (each severity strip summing to its lane
    count), stored CIS/compliance pass-rate, an asset count, and an
    identity/role count — everything scoped to ``account_ref`` (e.g.
    ``aws:123456789012``). Read-only: composes the #3946 rollup + scope filters
    over already-ingested evidence and never triggers a provider scan.

    Canonicalized + tenant-scoped; a malformed or unknown account returns an
    honest empty summary (all five lanes at zero, ``pass_rate: null``) rather
    than raising. The read runs off the event loop under the shared findings
    backpressure guard so a burst of account views cannot starve ``/health``.
    """
    tenant_id = _tenant(request)
    try:
        async with adaptive_backpressure("findings"):
            return await anyio.to_thread.run_sync(_build_account_summary, tenant_id, account_ref)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


@router.post("/cloud/runtime-evidence/ingest", tags=["cloud"])
async def cloud_runtime_evidence_ingest(
    request: Request,
    body: RuntimeEvidenceIngestRequest,
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Ingest source-scoped metadata using an existing API key or OIDC token.

    The verified credential must carry the exact runtime:ingest:<source_id>
    scope and have a lifetime of at most one hour. Source tenant/provider/account
    come from server registration. Credentials are never accepted in this body.
    Unknown, expired, revoked, unscoped or cross-tenant authority fails closed.
    """
    tenant_id = _tenant(request)

    def _ingest() -> dict[str, Any]:
        registry = get_runtime_source_registry()
        source = registry.get(body.source_id)
        # Tenant binding: the authenticated request tenant must own the source.
        # Fold "wrong tenant" into the same auth failure so a caller cannot probe
        # which source ids exist in another tenant.
        requested_tenant = request.headers.get("X-Agent-Bom-Tenant-ID")
        if source is None or source.tenant_id != tenant_id or (requested_tenant is not None and requested_tenant != tenant_id):
            raise SourceAuthenticationError("runtime evidence source authentication failed")
        # A cohort receipt does not grant authority over its named source.
        registry.authorize(body.source_id, principal)
        if body.validate_only and (body.correlation_cohort_id or body.correlation_child_receipt):
            raise CorrelationCohortIngestError("incomplete_receipt")
        cohort_id = (body.correlation_cohort_id or "").strip()
        cohort_receipt = body.correlation_child_receipt
        if bool(cohort_id) != bool(cohort_receipt):
            raise CorrelationCohortIngestError("incomplete_receipt")
        if cohort_id and cohort_receipt is not None:
            cohort_max_age_seconds = cohort_receipt.max_age_hours * 3600
            context = validate_correlation_cohort_child(
                tenant_id=tenant_id,
                source_id=body.source_id,
                correlation_cohort_id=cohort_id,
                receipt=cohort_receipt,
                allowed_source_kinds={"runtime.proxy", "runtime.gateway"},
            )
            request_hash = idempotency_request_fingerprint(
                {
                    "source_id": body.source_id,
                    "signals": [signal.model_dump(mode="json", exclude_none=True) for signal in body.signals],
                    "correlation_cohort_id": cohort_id,
                    "correlation_child_receipt": cohort_receipt.model_dump(mode="json"),
                }
            )

            def _reconcile_runtime_projection(completed_child: ScanJob | None = None) -> None:
                try:
                    projection = ingest_runtime_signals(
                        registry=registry,
                        source_id=body.source_id,
                        principal=principal,
                        raw_signals=[signal.model_dump(exclude_none=True) for signal in body.signals],
                        now=completed_child.completed_at if completed_child is not None else None,
                        max_age_seconds=cohort_max_age_seconds,
                        store=get_runtime_workload_evidence_store(),
                    )
                except Exception as exc:  # noqa: BLE001 - safe stable projection error below
                    raise CorrelationCohortIngestError("runtime_projection_unavailable") from exc
                if projection.rejected_incomplete:
                    raise CorrelationCohortIngestError("invalid_runtime_evidence")

            replay = prior_or_conflict(context.child, request_hash=request_hash)
            if replay is not None:
                # The graph/job commit is authoritative. Reconcile the derived
                # runtime lookup projection on replay if the process died in
                # the narrow post-commit window.
                _reconcile_runtime_projection(replay)
                return _runtime_cohort_response(replay)
            owner_token = idempotency_owner_token()
            lease_seconds = idempotency_reservation_lease_seconds()
            try:
                _receipt, claimed = _get_idempotency_store().claim(
                    "/v1/cloud/runtime-evidence/ingest/cohort",
                    tenant_id,
                    body.source_id,
                    context.child.job_id,
                    {"job_id": context.child.job_id, "committed": False},
                    request_hash=request_hash,
                    reservation_lease_seconds=lease_seconds,
                    owner_token=owner_token,
                )
            except IdempotencyConflictError as exc:
                raise CorrelationCohortIngestError("duplicate_result") from exc
            if not claimed:
                current = _get_store().get(context.child.job_id, tenant_id=tenant_id)
                replay = prior_or_conflict(current, request_hash=request_hash) if current is not None else None
                if replay is not None:
                    _reconcile_runtime_projection(replay)
                    return _runtime_cohort_response(replay)
                raise CorrelationCohortIngestError("child_commit_in_progress")

            heartbeat = IdempotencyReservationHeartbeat(
                _get_idempotency_store(),
                "/v1/cloud/runtime-evidence/ingest/cohort",
                tenant_id,
                body.source_id,
                context.child.job_id,
                request_hash=request_hash,
                owner_token=owner_token,
                lease_seconds=lease_seconds,
            )
            heartbeat.__enter__()
            heartbeat_stopped = False
            try:
                created_at = cohort_evidence_created_at(
                    [signal.observed_at for signal in body.signals],
                    max_age_hours=cohort_receipt.max_age_hours,
                )
                result = ingest_runtime_signals(
                    registry=registry,
                    source_id=body.source_id,
                    principal=principal,
                    raw_signals=[signal.model_dump(exclude_none=True) for signal in body.signals],
                    max_age_seconds=cohort_max_age_seconds,
                    store=None,
                )
                if not result.accepted or result.rejected_stale or result.rejected_incomplete:
                    raise CorrelationCohortIngestError("invalid_runtime_evidence")
                graph = _runtime_cohort_graph(
                    scan_id=context.child.job_id,
                    tenant_id=tenant_id,
                    created_at=created_at,
                    signals=result.accepted,
                )
                result_payload: dict[str, Any] = {
                    "scan_id": context.child.job_id,
                    "observed_at": created_at,
                    "runtime_evidence_ingest": result.to_dict(),
                }

                def _persist_runtime_graph(_job: ScanJob, _result: dict[str, Any]) -> None:
                    _get_graph_store().save_graph(graph)

                heartbeat.ensure_owned()
                heartbeat.__exit__()
                heartbeat_stopped = True

                def _commit_runtime_result() -> ScanJob:
                    child, _parent = commit_correlation_cohort_child(
                        context,
                        result=result_payload,
                        request_hash=request_hash,
                        persist_graph=_persist_runtime_graph,
                    )
                    _reconcile_runtime_projection(child)
                    return child

                child = _get_idempotency_store().commit_claim(
                    "/v1/cloud/runtime-evidence/ingest/cohort",
                    tenant_id,
                    body.source_id,
                    context.child.job_id,
                    lambda committed_child: {"job_id": committed_child.job_id, "committed": True},
                    action=_commit_runtime_result,
                    request_hash=request_hash,
                    owner_token=owner_token,
                )
                return _runtime_cohort_response(child)
            finally:
                if not heartbeat_stopped:
                    heartbeat.__exit__()
        result = ingest_runtime_signals(
            registry=registry,
            source_id=body.source_id,
            principal=principal,
            raw_signals=[s.model_dump(exclude_none=True) for s in body.signals],
            store=None if body.validate_only else get_runtime_workload_evidence_store(),
        )
        return result.to_dict()

    try:
        from agent_bom.api.runtime_source_auth import runtime_source_principal

        principal = await anyio.to_thread.run_sync(runtime_source_principal, request)
        async with adaptive_backpressure("runtime_evidence_ingest"):
            response = await anyio.to_thread.run_sync(_ingest)
        try:
            from agent_bom.api.audit_log import log_action

            await anyio.to_thread.run_sync(
                lambda: log_action(
                    "runtime_evidence.validate" if body.validate_only else "runtime_evidence.ingest",
                    actor=principal.subject,
                    tenant_id=tenant_id,
                    resource=f"runtime-evidence/source/{body.source_id}",
                    reason=body.reason,
                    persisted=response.get("persisted"),
                )
            )
            response["audit_status"] = "recorded"
        except Exception:
            _logger.warning("Runtime evidence audit event unavailable")
            response["status"] = "partial"
            response["audit_status"] = "unavailable"
        return response
    except SourceAuthenticationError as exc:
        # Never reveal whether the source exists or which credential check failed.
        raise HTTPException(status_code=401, detail="Runtime evidence source authentication failed") from exc
    except CorrelationCohortIngestError as exc:
        if exc.code == "incomplete_receipt":
            raise HTTPException(status_code=422, detail="Correlation cohort id and child receipt must be provided together") from exc
        if exc.code == "durable_store_required":
            detail = "Correlation cohort ingest requires durable stores"
        elif exc.code == "stale_evidence":
            detail = "Correlation cohort evidence is stale"
        elif exc.code in {"observation_time_required", "invalid_observation_time", "invalid_runtime_evidence"}:
            raise HTTPException(status_code=422, detail="Correlation cohort runtime evidence is incomplete") from exc
        elif exc.code == "duplicate_result":
            detail = "Correlation cohort child already has a different result"
        elif exc.code == "runtime_projection_unavailable":
            raise HTTPException(status_code=503, detail="Runtime evidence projection could not be committed") from exc
        else:
            detail = "Correlation cohort receipt is invalid"
        raise HTTPException(status_code=409, detail=detail) from exc
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _logger.error("Runtime evidence ingest failed")
        raise HTTPException(status_code=500, detail="Runtime evidence ingest failed; see server logs.") from exc


@router.post("/cloud/side-scan", tags=["cloud"])
async def cloud_side_scan_trigger(
    request: Request,
    body: SideScanTriggerRequest,
    _role: Any = _CIS_DEP,
) -> dict[str, Any]:
    """Trigger one cross-cloud (Azure/GCP) agentless disk side-scan (#4158 Wave 2).

    Runs the same shipped ``run_provider_side_scan`` executor the CLI
    (``agent-bom cloud side-scan``) uses, tenant-scoped and admin-gated. The heavy
    snapshot/mount/scan/teardown runs off the event loop in a worker thread under
    backpressure. The durable lifecycle record is returned so the caller can read
    honest terminal state — ``scan_complete`` / ``partial`` / ``failed`` plus
    cleanup status — never a false clean.

    Fail-closed and honest:
    - side-scan OFF (``AGENT_BOM_SIDESCAN`` unset) → ``200`` ``status=disabled``
      with enablement guidance (no cloud call is made).
    - provider extra / scoped lifecycle credentials unavailable → ``200``
      ``status=unavailable`` with the actionable, sanitized reason.
    - Azure requires ``collector_resource_group`` → ``400``.
    Credentials are never accepted here; the executor resolves separately
    scoped lifecycle credentials from the provider's default chain
    (``credentialed_smoke=false``).
    """
    from agent_bom.cloud.side_scan import SideScanConfigError, SideScanDisabledError
    from agent_bom.cloud.side_scan_lifecycle import SideScanStateConflictError, get_side_scan_state_store, new_side_scan_execution

    tenant_id = _tenant(request)
    provider = body.provider
    if provider == "azure" and not str(body.collector_resource_group or "").strip():
        raise HTTPException(
            status_code=400,
            detail="Azure Managed Disk side-scan requires 'collector_resource_group' for the in-account collector VM.",
        )

    import uuid as _uuid

    idempotency_key = (body.idempotency_key or _uuid.uuid4().hex).strip()
    # Deterministic execution id so the record is readable by execution_id after
    # the run, and so retries with the same idempotency key coalesce.
    execution_id = new_side_scan_execution(
        tenant_id=tenant_id,
        provider=provider,
        account_id=body.account_id.strip(),
        target_id=body.target_id.strip(),
        collector_id=body.collector_id.strip(),
        idempotency_key=idempotency_key,
    ).execution_id

    run_kwargs = dict(
        provider=provider,
        target_id=body.target_id.strip(),
        account_id=body.account_id.strip(),
        location=body.location.strip(),
        collector_id=body.collector_id.strip(),
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        collector_resource_group=body.collector_resource_group,
        region=body.region,
        scan_secrets_enabled=body.scan_secrets_enabled,
    )

    try:
        async with adaptive_backpressure("cloud_side_scan"):
            results = await anyio.to_thread.run_sync(lambda: _run_provider_side_scan_sync(**run_kwargs))
    except SideScanStateConflictError as exc:
        raise HTTPException(
            status_code=409, detail="Side-scan request conflicts with an existing execution; inspect its scope and state."
        ) from exc
    except SideScanDisabledError as exc:
        # The specific cause is logged server-side; the external response stays
        # generic so no exception detail reaches the caller (CodeQL:
        # information-exposure-through-an-exception).
        _logger.info("cloud_side_scan disabled for tenant %s: %s", sanitize_log_label(tenant_id), sanitize_text(sanitize_log_label(exc)))
        return {
            "status": "disabled",
            "execution_id": execution_id,
            "provider": provider,
            "tenant_id": tenant_id,
            "message": "Agentless disk side-scan is disabled on this instance.",
            "enable": "Set AGENT_BOM_SIDESCAN=1 and provide a scoped snapshot role plus an in-account collector.",
        }
    except SideScanConfigError as exc:
        # Provider extra missing / scoped lifecycle credentials unavailable / invalid
        # config. Degrade to an honest HTTP-200 unavailable envelope (mirrors the
        # CIS no-SDK path) rather than a 500 — never a false clean. The specific
        # cause is logged server-side; the external response stays generic so no
        # exception detail is exposed to the caller.
        _logger.warning(
            "cloud_side_scan unavailable for %s tenant %s: %s",
            sanitize_log_value(provider),
            sanitize_log_value(tenant_id),
            sanitize_text(sanitize_log_value(sanitize_log_label(exc))),
        )
        return {
            "status": "unavailable",
            "execution_id": execution_id,
            "provider": provider,
            "tenant_id": tenant_id,
            "reason": "Provider side-scan configuration or scoped lifecycle credentials are unavailable; see server logs for the cause.",
        }
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Failures may precede resource creation; do not infer cleanup success.
        _logger.error("Cloud side-scan execution failed")
        raise HTTPException(
            status_code=500, detail="Cloud side-scan failed; inspect execution history for scan and cleanup state."
        ) from exc

    store = get_side_scan_state_store()
    record = store.get(tenant_id=tenant_id, execution_id=execution_id)
    payload: dict[str, Any] = {
        "status": record.status.value if record is not None else "unknown",
        "execution_id": execution_id,
        "provider": provider,
        "tenant_id": tenant_id,
        "result": _side_scan_result_summary(results),
    }
    if record is not None:
        payload["execution"] = record.to_dict()
        payload["evidence"] = record.to_evidence_dict()
    return payload


@router.get("/cloud/side-scan", **documented(rt.CloudSideScanListResponse), tags=["cloud"])
async def cloud_side_scan_list(
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max executions to return (newest first)."),
    offset: int = Query(0, ge=0, le=100_000, description="Zero-based execution offset."),
    provider: Literal["aws", "azure", "gcp"] | None = Query(None, description="Optional provider filter."),
    status: Literal["queued", "running", "scan_complete", "partial", "disabled", "denied", "failed"] | None = Query(
        None,
        description="Optional lifecycle status filter.",
    ),
    q: str = Query("", max_length=200, description="Optional target, account, or execution-id search."),
    _role: Any = _READ_DEP,
) -> dict[str, Any]:
    """List recent Azure/GCP side-scan executions + provider executor capabilities.

    Read-only over the shared lifecycle store, tenant-scoped — never crosses the
    tenant boundary and never triggers a scan. ``capabilities`` reflects the honest
    per-provider executor surface (``credentialed_smoke`` stays false until a live
    run is proven). Powers the CWPP side-scan UI.
    """
    from agent_bom.cloud.side_scan_lifecycle import get_side_scan_state_store, side_scan_provider_capabilities

    tenant_id = _tenant(request)

    def _read() -> dict[str, Any]:
        store = get_side_scan_state_store()
        records, total = store.list_page_with_total(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            provider=provider,
            status=status,
            query=q,
        )
        capabilities = [cap.to_dict() for cap in side_scan_provider_capabilities().values()]
        return {
            "tenant_id": tenant_id,
            "executions": [record.to_dict() for record in records],
            "page": {
                "limit": limit,
                "offset": offset,
                "returned": len(records),
                "total": total,
                "has_more": offset + len(records) < total,
                "completeness": "complete",
            },
            "capabilities": capabilities,
            "credentialed_smoke": False,
        }

    try:
        async with adaptive_backpressure("findings"):
            return await anyio.to_thread.run_sync(_read)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


@router.get("/cloud/side-scan/{execution_id}", **documented(rt.CloudSideScanStatusResponse), tags=["cloud"])
async def cloud_side_scan_status(
    request: Request,
    execution_id: str,
    _role: Any = _READ_DEP,
) -> dict[str, Any]:
    """Read one side-scan execution's status + metadata-only evidence by id.

    Tenant-scoped read from the shared lifecycle store; an unknown id (or one
    owned by another tenant) returns ``404``. Never triggers a scan.
    """
    from agent_bom.cloud.side_scan_lifecycle import get_side_scan_state_store

    tenant_id = _tenant(request)
    scoped_id = execution_id.strip()
    if not scoped_id or len(scoped_id) > 128:
        raise HTTPException(status_code=404, detail="Side-scan execution not found.")

    def _read() -> dict[str, Any] | None:
        store = get_side_scan_state_store()
        record = store.get(tenant_id=tenant_id, execution_id=scoped_id)
        if record is None:
            return None
        return {
            "status": record.status.value,
            "execution_id": record.execution_id,
            "provider": record.provider,
            "tenant_id": tenant_id,
            "execution": record.to_dict(),
            "evidence": record.to_evidence_dict(),
        }

    try:
        async with adaptive_backpressure("findings"):
            payload = await anyio.to_thread.run_sync(_read)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    if payload is None:
        raise HTTPException(status_code=404, detail="Side-scan execution not found.")
    return payload


_EXPORTS = {
    "_snowflake_inventory": "agent_bom.api.cloud_inventory_read",
    "_CIS_SECTIONS": "agent_bom.api.cloud_summary_read",
    "_cis_block_account_id": "agent_bom.api.cloud_summary_read",
    "_cis_counts": "agent_bom.api.cloud_summary_read",
    "_SIDESCAN_PROVIDERS": "agent_bom.api.cloud_scan_results",
    "_PERMISSION_RE": "agent_bom.api.cloud_response_helpers",
    "_SCOPE_RE": "agent_bom.api.cloud_response_helpers",
    "_AUDIT_ENUM_RE": "agent_bom.api.cloud_response_helpers",
    "_clean_tokens": "agent_bom.api.cloud_response_helpers",
    "_redact_summary": "agent_bom.api.cloud_response_helpers",
    "_audit_metadata": "agent_bom.api.cloud_response_helpers",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
