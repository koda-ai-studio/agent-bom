"""AI-powered enrichment — LLM-generated risk narratives, executive summaries, and threat chains.

Supports three LLM backends (in priority order):

1. **Ollama (free, local)** — auto-detected at ``http://localhost:11434``.
   No extra install needed (uses httpx, already a core dependency).
   Start with: ``ollama serve`` then ``ollama pull llama3.2``

2. **HuggingFace Inference API (free tier)** — open-source models in the cloud.
   Install with: ``pip install 'agent-bom[huggingface]'``
   Set ``HF_TOKEN`` env var for gated models.

3. **litellm (100+ providers)** — OpenAI, Anthropic, Mistral, Groq, etc.
   Install with: ``pip install 'agent-bom[ai-enrich]'``

All LLM calls are:
- **Optional**: graceful fallback when no provider is available.
- **Cached**: in-memory dedup by ``sha256(model:prompt)`` within a scan run.
- **Batched**: grouped by package to minimize API calls.
- **Structured**: Pydantic schemas + Ollama's ``format`` parameter for reliable JSON."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from agent_bom import config
from agent_bom.ai_components.ai_prompts import _ASSIGNMENT_PATTERN as _ASSIGNMENT_PATTERN
from agent_bom.ai_components.ai_prompts import _IDENTIFIER_RE as _IDENTIFIER_RE
from agent_bom.ai_components.ai_prompts import _MAX_AI_PROMPT_CHARS as _MAX_AI_PROMPT_CHARS
from agent_bom.ai_components.ai_prompts import _MAX_AI_SKILL_FILE_CHARS as _MAX_AI_SKILL_FILE_CHARS
from agent_bom.ai_components.ai_prompts import _MAX_AI_SKILL_FILES as _MAX_AI_SKILL_FILES
from agent_bom.ai_components.ai_prompts import _MAX_AI_SKILL_FINDINGS as _MAX_AI_SKILL_FINDINGS
from agent_bom.ai_components.ai_prompts import _PROMPT_TRUNCATION_MARKER as _PROMPT_TRUNCATION_MARKER
from agent_bom.ai_components.ai_prompts import _SECRET_PATTERNS as _SECRET_PATTERNS
from agent_bom.ai_components.ai_prompts import _bounded_ai_text as _bounded_ai_text
from agent_bom.ai_components.ai_prompts import _bounded_prompt_list as _bounded_prompt_list
from agent_bom.ai_components.ai_prompts import _bounded_prompt_text as _bounded_prompt_text
from agent_bom.ai_components.ai_prompts import _build_blast_radius_prompt as _build_blast_radius_prompt
from agent_bom.ai_components.ai_prompts import _build_executive_summary_prompt as _build_executive_summary_prompt
from agent_bom.ai_components.ai_prompts import _build_finding_assessment_prompt as _build_finding_assessment_prompt
from agent_bom.ai_components.ai_prompts import _build_mcp_config_analysis_prompt as _build_mcp_config_analysis_prompt
from agent_bom.ai_components.ai_prompts import _build_skill_analysis_prompt as _build_skill_analysis_prompt
from agent_bom.ai_components.ai_prompts import _build_threat_chain_prompt as _build_threat_chain_prompt
from agent_bom.ai_components.ai_prompts import _canonical_skill_source_path as _canonical_skill_source_path
from agent_bom.ai_components.ai_prompts import _compose_bounded_prompt as _compose_bounded_prompt
from agent_bom.ai_components.ai_prompts import _looks_like_secret_value as _looks_like_secret_value
from agent_bom.ai_components.ai_prompts import _redact_assignment as _redact_assignment
from agent_bom.ai_components.ai_prompts import redact_secrets as redact_secrets
from agent_bom.security import sanitize_error

if TYPE_CHECKING:
    from agent_bom.ai_schemas import AIFindingAssessment, MCPConfigSecurityAnalysis
    from agent_bom.models import AIBOMReport, BlastRadius
    from agent_bom.parsers.skill_audit import SkillAuditResult
    from agent_bom.parsers.skills import SkillScanResult
from importlib import import_module
from typing import Any

from agent_bom.ai_components.call_state import (
    _AI_DETERMINISTIC_OVERRIDE,
    _AI_RUN_ID,
    AI_PROMPT_VERSION,
    DEFAULT_MODEL,
    AICallBudget,
    EnrichmentTask,
    _effective_temperature,
    _prepare_prompt,
    console,
    logger,
    resolve_task_model,
)
from agent_bom.ai_components.provider_discovery import _has_any_provider, _resolve_ai_provider
from agent_bom.ai_components.providers import _call_llm, _call_llm_structured, _parse_json_response

_DEFAULT_AI_MAX_CALLS = 50  # Hard cap: prevent runaway spend on large monorepos


async def enrich_blast_radii(
    blast_radii: list[BlastRadius],
    model: str = DEFAULT_MODEL,
    max_calls: int = _DEFAULT_AI_MAX_CALLS,
    budget: AICallBudget | None = None,
) -> int:
    """Add AI-generated risk narratives to blast radius findings.

    Groups findings by package to minimize API calls (one call per unique
    package, regardless of how many CVEs affect it).

    ``max_calls`` caps total LLM requests per scan run to prevent runaway
    API spend on large monorepos.  Defaults to 50; pass ``max_calls=0`` to
    disable the cap.  Returns count of enriched findings.
    """
    if not blast_radii:
        return 0
    if not _has_any_provider(model):
        return 0

    enriched = 0
    calls_made = 0
    seen_packages: dict[str, Optional[str]] = {}  # pkg_key -> ai_summary

    for br in blast_radii:
        pkg_key = f"{br.package.ecosystem}:{br.package.name}@{br.package.version}"

        if pkg_key in seen_packages:
            cached = seen_packages[pkg_key]
            if cached:
                br.ai_summary = cached
                enriched += 1
            continue

        if max_calls and calls_made >= max_calls:
            logger.warning(
                "AI enrichment cap reached (%d unique-package calls). Pass max_calls= to enrich_blast_radii() to increase the limit.",
                max_calls,
            )
            break

        prompt = _build_blast_radius_prompt(br)
        result = await _call_llm(prompt, model, task=EnrichmentTask.NARRATIVE, budget=budget)
        if budget is not None and budget.to_dict()["exhausted"] and result is None:
            logger.warning("AI provider-attempt budget exhausted before narrative enrichment completed")
        seen_packages[pkg_key] = result
        calls_made += 1
        if result:
            br.ai_summary = result
            enriched += 1

    return enriched


async def generate_executive_summary(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    budget: AICallBudget | None = None,
) -> Optional[str]:
    """Generate an LLM-powered executive summary of the scan."""
    if not report.blast_radii:
        return None
    if not _has_any_provider(model):
        return None
    prompt = _build_executive_summary_prompt(report)
    return await _call_llm(prompt, model, max_tokens=300, task=EnrichmentTask.SUMMARY, budget=budget)


async def generate_threat_chains(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    budget: AICallBudget | None = None,
) -> list[str]:
    """Generate LLM-powered threat chain analysis."""
    if not report.blast_radii:
        return []
    if not _has_any_provider(model):
        return []
    prompt = _build_threat_chain_prompt(report)
    result = await _call_llm(prompt, model, max_tokens=800, task=EnrichmentTask.SUMMARY, budget=budget)
    return [result] if result else []


def _parse_finding_assessments(
    response: str,
    *,
    known_ids: set[str],
    provider: str,
    model: str,
    run_id: str,
    prompt: str,
) -> list["AIFindingAssessment"]:
    from pydantic import ValidationError

    from agent_bom.ai_schemas import (
        AIFindingAssessment,
        AIFindingAssessmentResponse,
        AIProvenance,
    )

    data = _parse_json_response(response)
    if not isinstance(data, dict):
        return []
    try:
        parsed = AIFindingAssessmentResponse.model_validate(data)
    except ValidationError as exc:
        logger.warning("AI finding assessment response rejected: %s", sanitize_error(exc, generic=True))
        return []

    accepted: list[AIFindingAssessment] = []
    seen_ids: set[str] = set()
    prompt_sha256 = hashlib.sha256(_prepare_prompt(prompt).encode()).hexdigest()
    response_sha256 = hashlib.sha256(response.encode()).hexdigest()
    generated_at = datetime.now(timezone.utc)
    for candidate in parsed.assessments:
        finding_id = candidate.finding_id
        if finding_id not in known_ids or finding_id in seen_ids:
            continue
        seen_ids.add(finding_id)
        controls = list(dict.fromkeys(candidate.suggested_controls))[:10]
        accepted.append(
            AIFindingAssessment(
                finding_id=finding_id,
                classification=candidate.classification,
                confidence=candidate.confidence,
                false_positive_likelihood=candidate.false_positive_likelihood,
                rationale=candidate.rationale,
                suggested_controls=controls,
                provenance=AIProvenance(
                    run_id=run_id,
                    provider=provider,
                    model=model,
                    model_revision=str(getattr(config, "AI_MODEL_REVISION", "") or ""),
                    prompt_version=AI_PROMPT_VERSION,
                    prompt_sha256=prompt_sha256,
                    response_sha256=response_sha256,
                    generated_at=generated_at,
                    deterministic=_effective_temperature() == 0.0,
                    redaction_applied=bool(getattr(config, "AI_REDACT_PROMPTS", True)),
                ),
            )
        )
    return accepted


async def assess_report_findings(
    report: "AIBOMReport",
    model: str = DEFAULT_MODEL,
    *,
    provider: str = "unknown",
    budget: AICallBudget | None = None,
    run_id: str | None = None,
) -> list["AIFindingAssessment"]:
    """Return immutable, provenance-scored AI triage for deterministic findings."""
    if not _has_any_provider(model):
        return []
    max_findings = int(getattr(config, "AI_MAX_FINDINGS_PER_RUN", 100))
    if max_findings < 0:
        raise ValueError("AGENT_BOM_AI_MAX_FINDINGS must be non-negative")
    if max_findings == 0:
        return []
    findings = report.to_findings()[:max_findings]
    if not findings:
        return []
    batch_size = max(1, min(int(getattr(config, "AI_FINDING_BATCH_SIZE", 20)), 50))
    assessments: list[AIFindingAssessment] = []
    active_run_id = run_id or str(uuid.uuid4())
    for offset in range(0, len(findings), batch_size):
        batch = findings[offset : offset + batch_size]
        prompt = _build_finding_assessment_prompt(batch)
        response = await _call_llm(
            prompt,
            model,
            max_tokens=1800,
            task=EnrichmentTask.TRIAGE,
            budget=budget,
        )
        if not response:
            if budget is not None and budget.to_dict()["exhausted"]:
                logger.warning("AI provider-attempt budget exhausted before finding triage completed")
                break
            continue
        assessments.extend(
            _parse_finding_assessments(
                response,
                known_ids={finding.id for finding in batch},
                provider=provider,
                model=model,
                run_id=active_run_id,
                prompt=prompt,
            )
        )
    return assessments


async def _run_ai_enrichment_impl(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    skill_result: "SkillScanResult | None" = None,
    skill_audit: "SkillAuditResult | None" = None,
    *,
    gate_ai_findings: bool = False,
) -> None:
    """Run all AI enrichment steps on a report. Modifies report in-place."""
    budget = AICallBudget(max_calls=int(getattr(config, "AI_MAX_CALLS_PER_RUN", 50)))
    run_id = _AI_RUN_ID.get() or str(uuid.uuid4())
    resolution = _resolve_ai_provider(model)
    report.ai_enrichment_metadata = {
        **resolution.to_metadata(),
        "run_id": run_id,
        "call_budget": budget.to_dict(),
    }
    if not resolution.available:
        console.print("  [yellow]No LLM provider available. Skipping AI enrichment.[/yellow]")
        console.print("  [dim]Option 1: Install Ollama (free, local) — ollama.com[/dim]")
        console.print("  [dim]Option 2: pip install 'agent-bom[huggingface]' + set HF_TOKEN[/dim]")
        console.print("  [dim]Option 3: pip install 'agent-bom[ai-enrich]' + set API key[/dim]")
        return

    model = resolution.model
    provider = resolution.provider.display_name if resolution.provider else "unknown"

    # Per-task model selection: cheap tier for narratives/summaries, strong tier
    # for config analysis. Tiers fall back to the resolved model when unset.
    narrative_model = resolve_task_model(EnrichmentTask.NARRATIVE, model)
    summary_model = resolve_task_model(EnrichmentTask.SUMMARY, model)
    config_model = resolve_task_model(EnrichmentTask.CONFIG_ANALYSIS, model)
    triage_model = resolve_task_model(EnrichmentTask.TRIAGE, model)

    # Provenance: record the full harness posture, not just the primary model.
    report.ai_enrichment_metadata = {
        **resolution.to_metadata(),
        "harness_version": "2",
        "run_id": run_id,
        "model_revision": str(getattr(config, "AI_MODEL_REVISION", "") or ""),
        "prompt_version": AI_PROMPT_VERSION,
        "task_models": {
            "narrative": narrative_model,
            "summary": summary_model,
            "config_analysis": config_model,
            "triage": triage_model,
        },
        "redaction": bool(getattr(config, "AI_REDACT_PROMPTS", True)),
        "deterministic": _effective_temperature() == 0.0,
        "temperature": _effective_temperature(),
        "advisory_default": True,
        "ai_gate_enabled": gate_ai_findings,
        "call_budget": budget.to_dict(),
    }

    console.print(f"\n[bold blue]AI Enrichment[/bold blue]  [dim]model: {model} via {provider}[/dim]\n")

    # Advisory triage is the primary structured surface, so it receives budget
    # before optional narrative generation on large estates.
    triage_resolution = _resolve_ai_provider(triage_model)
    assessments = await assess_report_findings(
        report,
        triage_resolution.model if triage_resolution.available else triage_model,
        provider=triage_resolution.provider.name if triage_resolution.provider else "unknown",
        budget=budget,
        run_id=run_id,
    )
    total_findings = len(report.to_findings())
    max_findings = int(getattr(config, "AI_MAX_FINDINGS_PER_RUN", 100))
    report.ai_enrichment_metadata["triage_scope"] = {
        "findings_total": total_findings,
        "findings_offered": min(total_findings, max_findings),
        "findings_truncated": max(total_findings - max_findings, 0),
        "assessments_generated": len(assessments),
    }
    if assessments:
        report.ai_finding_assessments = assessments
        console.print(f"  [green]{len(assessments)} advisory finding assessment(s) generated[/green]")

    # Step 1: Enrich blast radii with contextual narratives
    if report.blast_radii:
        console.print("  [cyan]>[/cyan] Generating risk narratives...")
        enriched = await enrich_blast_radii(report.blast_radii, narrative_model, budget=budget)
        console.print(f"  [green]{enriched} finding(s) enriched[/green]")

        # Step 2: Generate executive summary
        console.print("  [cyan]>[/cyan] Generating executive summary...")
        summary = await generate_executive_summary(report, summary_model, budget)
        if summary:
            report.executive_summary = summary
            console.print("  [green]Executive summary generated[/green]")

        # Step 3: Generate threat chain analysis
        console.print("  [cyan]>[/cyan] Analyzing threat chains...")
        chains = await generate_threat_chains(report, summary_model, budget)
        if chains:
            report.ai_threat_chains = chains
            console.print(f"  [green]{len(chains)} threat chain(s) analyzed[/green]")

    # Step 4: MCP config security analysis
    total_servers = sum(len(a.mcp_servers) for a in report.agents)
    if total_servers > 0:
        console.print("  [cyan]>[/cyan] Analyzing MCP config security...")
        config_analysis = await analyze_mcp_config_security(report, config_model, budget)
        if config_analysis:
            report.mcp_config_analysis = config_analysis.model_dump()
            console.print(f"  [green]Config analysis complete (risk: {config_analysis.overall_risk})[/green]")

    # Step 5: Skill file AI analysis
    if skill_result and skill_audit and skill_result.raw_content:
        console.print("  [cyan]>[/cyan] Analyzing skill file security...")
        skill_enriched = await enrich_skill_audit(
            skill_result,
            skill_audit,
            model,
            gate_ai_findings=gate_ai_findings,
            budget=budget,
        )
        if skill_enriched:
            console.print(f"  [green]Skill files analyzed (risk: {skill_audit.ai_overall_risk_level or 'unknown'})[/green]")
        else:
            console.print("  [dim]  Skill analysis could not be completed[/dim]")

    report.ai_enrichment_metadata["call_budget"] = budget.to_dict()


async def run_ai_enrichment(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    skill_result: "SkillScanResult | None" = None,
    skill_audit: "SkillAuditResult | None" = None,
    *,
    deterministic: bool | None = None,
    gate_ai_findings: bool = False,
) -> None:
    """Run enrichment with a task-local deterministic-mode override."""
    deterministic_token = _AI_DETERMINISTIC_OVERRIDE.set(deterministic)
    run_token = _AI_RUN_ID.set(str(uuid.uuid4()))
    try:
        if gate_ai_findings and _effective_temperature() != 0.0:
            raise ValueError("AI finding gating requires deterministic mode")
        await _run_ai_enrichment_impl(
            report,
            model,
            skill_result,
            skill_audit,
            gate_ai_findings=gate_ai_findings,
        )
    finally:
        _AI_RUN_ID.reset(run_token)
        _AI_DETERMINISTIC_OVERRIDE.reset(deterministic_token)


def run_ai_enrichment_sync(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    skill_result: "SkillScanResult | None" = None,
    skill_audit: "SkillAuditResult | None" = None,
    *,
    deterministic: bool | None = None,
    gate_ai_findings: bool = False,
) -> None:
    """Synchronous wrapper for run_ai_enrichment."""
    asyncio.run(
        run_ai_enrichment(
            report,
            model,
            skill_result,
            skill_audit,
            deterministic=deterministic,
            gate_ai_findings=gate_ai_findings,
        )
    )


def _parse_skill_analysis_response(response: str) -> dict | None:
    """Parse the LLM's skill analysis JSON response.

    Uses the generic ``_parse_json_response`` and validates that the result
    contains the expected ``overall_risk_level`` key.
    """
    from pydantic import ValidationError

    from agent_bom.ai_schemas import SkillAnalysisResult

    data = _parse_json_response(response)
    if not isinstance(data, dict):
        logger.warning("Could not parse skill analysis LLM response as JSON")
        return None
    try:
        return SkillAnalysisResult.model_validate(data).model_dump()
    except ValidationError as exc:
        logger.warning("Skill analysis response rejected: %s", sanitize_error(exc, generic=True))
        return None


def _apply_skill_analysis(
    audit: "SkillAuditResult",
    ai_data: dict,
    *,
    ai_source: str | None = None,
    ai_model: str | None = None,
    gate_ai_findings: bool = False,
    analyzed_source_files: tuple[str, ...] = (),
) -> None:
    """Apply parsed AI analysis results to a SkillAuditResult in-place.

    Updates existing findings with AI verdicts and adds new AI-detected
    findings. Deterministic pass/fail is preserved unless the caller explicitly
    opts into AI gating after selecting deterministic model execution.
    """
    from agent_bom.ai_schemas import SkillAnalysisResult
    from agent_bom.parsers.skill_audit import SkillFinding

    parsed = SkillAnalysisResult.model_validate(ai_data)

    # Capture the deterministic result exactly once, before AI annotations.
    if audit.deterministic_passed is None:
        audit.deterministic_passed = audit.passed
    audit.ai_gate_enabled = gate_ai_findings

    # Set top-level AI fields
    audit.ai_overall_risk_level = parsed.overall_risk_level
    audit.ai_skill_summary = parsed.summary

    # Build a lookup of existing findings by title for matching
    findings_by_title: dict[str, SkillFinding] = {}
    for finding in audit.findings:
        findings_by_title[finding.title] = finding

    # Apply finding reviews
    for review in parsed.finding_reviews:
        title = review.title or review.original_title
        matched = findings_by_title.get(title)
        if not matched:
            continue

        verdict = review.verdict
        matched.ai_analysis = review.reasoning
        matched.ai_source = ai_source
        matched.ai_model = ai_model
        matched.ai_confidence = review.confidence

        if verdict == "false_positive":
            matched.ai_adjusted_severity = "false_positive"
        elif verdict == "severity_adjusted":
            if review.adjusted_severity is not None:
                matched.ai_adjusted_severity = review.adjusted_severity

    # Add new AI-detected findings
    allowed_source_files = {_canonical_skill_source_path(source_file) for source_file in analyzed_source_files}
    for new in parsed.new_findings:
        source = new.source_file if new.source_file in allowed_source_files else "unknown"

        audit.findings.append(
            SkillFinding(
                severity=new.severity,
                category=new.category,
                title=new.title,
                detail=new.detail,
                source_file=source,
                recommendation=new.recommendation,
                context="ai_analysis",
                ai_source=ai_source,
                ai_model=ai_model,
                ai_confidence=new.confidence,
                ai_detected=True,
            )
        )

    if gate_ai_findings:
        # Explicit opt-in only: false-positive reviews and AI-detected findings
        # may affect the result, but only high-confidence model judgments can
        # change the deterministic gate. Missing confidence normalizes to low.
        def _blocks_gate(finding: SkillFinding) -> bool:
            if finding.ai_detected:
                return finding.ai_confidence == "high" and finding.severity in ("critical", "high")
            effective_severity = finding.severity
            if finding.ai_confidence == "high":
                if finding.ai_adjusted_severity == "false_positive":
                    return False
                if finding.ai_adjusted_severity in ("critical", "high", "medium", "low"):
                    effective_severity = finding.ai_adjusted_severity
            return effective_severity in ("critical", "high")

        audit.passed = not any(_blocks_gate(finding) for finding in audit.findings)
    else:
        audit.passed = audit.deterministic_passed


async def enrich_skill_audit(
    skill_result: "SkillScanResult",
    skill_audit: "SkillAuditResult",
    model: str = DEFAULT_MODEL,
    *,
    gate_ai_findings: bool = False,
    budget: AICallBudget | None = None,
) -> bool:
    """Orchestrate AI-powered skill file security analysis.

    Sends raw skill file content and static findings to an LLM for
    context-aware analysis, then applies the results to the audit.

    Returns True if enrichment was applied, False otherwise.
    """
    # Guard: need raw content to analyze
    if not skill_result.raw_content:
        logger.debug("No raw content available for skill AI enrichment")
        return False

    # Guard: need an LLM provider
    resolution = _resolve_ai_provider(model)
    if not resolution.available:
        logger.debug("No LLM provider available for skill enrichment")
        return False
    if resolution.provider is None or not resolution.provider.local:
        logger.warning("Raw skill-file AI analysis skipped because the selected provider is not local")
        return False
    resolved_model = resolution.model

    # Serialize static findings as list of dicts
    static_findings = [
        {
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "detail": f.detail,
            "source_file": f.source_file,
            "context": f.context,
        }
        for f in skill_audit.findings
    ]

    # Build prompt and call LLM
    prompt = _build_skill_analysis_prompt(skill_result.raw_content, static_findings)
    response = await _call_llm(
        prompt,
        resolved_model,
        max_tokens=1500,
        task=EnrichmentTask.DETECTION,
        budget=budget,
    )

    if not response:
        logger.warning("LLM returned empty response for skill analysis")
        return False

    # Parse and apply
    ai_data = _parse_skill_analysis_response(response)
    if ai_data is None:
        logger.warning("Could not parse LLM skill analysis response")
        return False

    try:
        _apply_skill_analysis(
            skill_audit,
            ai_data,
            ai_source=resolution.provider.name,
            ai_model=resolved_model,
            gate_ai_findings=gate_ai_findings,
            analyzed_source_files=tuple(list(skill_result.raw_content)[:_MAX_AI_SKILL_FILES]),
        )
    except (TypeError, ValueError) as exc:
        logger.warning("Skill analysis could not be applied: %s", sanitize_error(exc, generic=True))
        return False
    return True


async def analyze_mcp_config_security(
    report: "AIBOMReport",
    model: str = DEFAULT_MODEL,
    budget: AICallBudget | None = None,
) -> Optional["MCPConfigSecurityAnalysis"]:
    """Run LLM-powered MCP configuration security analysis.

    Examines the full configuration surface — not individual CVEs — for
    architectural security risks like missing auth, overpermission, AWM patterns.
    """
    from agent_bom.ai_schemas import MCPConfigSecurityAnalysis

    total_servers = sum(len(a.mcp_servers) for a in report.agents)
    if total_servers == 0:
        return None
    if not _has_any_provider(model):
        return None
    prompt = _build_mcp_config_analysis_prompt(report)

    # Budgeted orchestration uses exactly one provider call. The legacy direct
    # function path retains native structured output plus its fallback.
    if budget is not None:
        raw = await _call_llm(
            prompt,
            model,
            max_tokens=1000,
            task=EnrichmentTask.CONFIG_ANALYSIS,
            budget=budget,
        )
        parsed = _parse_json_response(raw) if raw else None
        if parsed:
            try:
                return MCPConfigSecurityAnalysis.model_validate(parsed)
            except (ValueError, TypeError, KeyError) as exc:
                logger.debug("Failed to validate MCPConfigSecurityAnalysis: %s", sanitize_error(exc, generic=True))
        return None

    # Try structured output first
    result = await _call_llm_structured(prompt, model, MCPConfigSecurityAnalysis, max_tokens=1000)
    if result:
        return result  # type: ignore[return-value]

    # Fallback to unstructured
    raw = await _call_llm(prompt, model, max_tokens=1000)
    if raw:
        parsed = _parse_json_response(raw)
        if parsed:
            try:
                return MCPConfigSecurityAnalysis.model_validate(parsed)
            except (ValueError, TypeError, KeyError) as exc:
                logger.debug("Failed to validate MCPConfigSecurityAnalysis: %s", sanitize_error(exc, generic=True))
    return None


_EXPORTS = {
    "_cache": "agent_bom.ai_components.call_state",
    "_cache_lock": "agent_bom.ai_components.call_state",
    "_response_text": "agent_bom.ai_components.call_state",
    "_ai_cache_get": "agent_bom.ai_components.call_state",
    "_ai_cache_put": "agent_bom.ai_components.call_state",
    "OLLAMA_DEFAULT_MODEL": "agent_bom.ai_components.call_state",
    "HF_DEFAULT_MODEL": "agent_bom.ai_components.call_state",
    "OLLAMA_MODEL_PREFERENCE": "agent_bom.ai_components.call_state",
    "AIProviderDescriptor": "agent_bom.ai_components.provider_discovery",
    "AIProviderStatus": "agent_bom.ai_components.provider_discovery",
    "AIProviderResolution": "agent_bom.ai_components.provider_discovery",
    "AI_PROVIDER_DESCRIPTORS": "agent_bom.ai_components.provider_discovery",
    "_check_litellm": "agent_bom.ai_components.provider_discovery",
    "_check_huggingface": "agent_bom.ai_components.provider_discovery",
    "_detect_ollama": "agent_bom.ai_components.provider_discovery",
    "_get_ollama_models": "agent_bom.ai_components.provider_discovery",
    "_provider_name_for_model": "agent_bom.ai_components.provider_discovery",
    "_ollama_endpoint_is_loopback": "agent_bom.ai_components.provider_discovery",
    "_url_is_loopback": "agent_bom.ai_components.provider_discovery",
    "_LITELLM_MODEL_CREDENTIALS": "agent_bom.ai_components.provider_discovery",
    "_litellm_readiness": "agent_bom.ai_components.provider_discovery",
    "_provider_status": "agent_bom.ai_components.provider_discovery",
    "describe_ai_providers": "agent_bom.ai_components.provider_discovery",
    "_resolve_model": "agent_bom.ai_components.provider_discovery",
    "_request_timeout": "agent_bom.ai_components.call_state",
    "_T": "agent_bom.ai_components.call_state",
    "_RETRYABLE_EXC": "agent_bom.ai_components.call_state",
    "retry_async": "agent_bom.ai_components.call_state",
    "_TASK_TIER": "agent_bom.ai_components.call_state",
    "EnrichmentProvider": "agent_bom.ai_components.providers",
    "OllamaProvider": "agent_bom.ai_components.providers",
    "HuggingFaceProvider": "agent_bom.ai_components.providers",
    "LiteLLMProvider": "agent_bom.ai_components.providers",
    "PROVIDER_REGISTRY": "agent_bom.ai_components.providers",
    "get_provider": "agent_bom.ai_components.providers",
    "provider_for_model": "agent_bom.ai_components.providers",
    "_cache_key": "agent_bom.ai_components.providers",
    "_call_ollama_direct": "agent_bom.ai_components.providers",
    "_call_llm_via_litellm": "agent_bom.ai_components.providers",
    "_call_huggingface": "agent_bom.ai_components.providers",
    "_call_ollama_structured": "agent_bom.ai_components.providers",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
