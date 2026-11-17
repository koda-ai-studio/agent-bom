"""OpenAI platform discovery — completed fine-tuning jobs.

Requires ``openai``.  Install with::

    pip install 'agent-bom[openai]'

Authentication uses OPENAI_API_KEY env var or --openai-api-key flag.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, ServerSurface, TransportType

from .base import CloudDiscoveryError
from .normalization import build_cloud_origin

logger = logging.getLogger(__name__)


def discover(
    api_key: str | None = None,
    organization: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI assets from the OpenAI platform.

    Discovers completed fine-tunes and referenced training-file IDs.
    Retired Assistants and Responses application inventory are not collected.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``openai`` is not installed.
    """
    try:
        import openai  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError("openai is required for OpenAI discovery. Install with: pip install 'agent-bom[openai]'")

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_key = api_key or os.environ.get("OPENAI_API_KEY", "")
    resolved_org = organization or os.environ.get("OPENAI_ORG_ID", "")

    if not resolved_key:
        warnings.append("OPENAI_API_KEY not set. Provide --openai-api-key or set the OPENAI_API_KEY env var.")
        return agents, warnings

    warnings.append(
        "openai:assistants:unsupported: The Assistants API is retired. "
        "Responses application inventory is not collected; assessment coverage is limited to fine-tuning jobs."
    )
    ft_agents, ft_warns = _discover_fine_tunes(resolved_key, resolved_org)
    agents.extend(ft_agents)
    warnings.extend(ft_warns)

    # Per-run discovery envelope (#2083 PR B).
    scope: list[str] = []
    if resolved_org:
        scope.append(f"openai:organization/{resolved_org}")
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.SAAS_READ_ONLY,
        discovery_scope=tuple(scope),
        permissions_used=("openai:fine_tuning.jobs:list",),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )
    return agents, warnings


def _read_failure(exc: Exception) -> str:
    """Classify provider failures without including credential-bearing diagnostics."""
    code = getattr(exc, "status_code", None)
    status = {401: "denied", 403: "denied", 429: "throttled"}.get(code if isinstance(code, int) else 0, "unavailable")
    return f"openai:fine-tuning:{status}: Could not read inventory; assessment incomplete. Check read access or retry later."


def _discover_fine_tunes(
    api_key: str,
    organization: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover fine-tuned models from OpenAI."""
    import openai

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        kwargs: dict = {"api_key": api_key}
        if organization:
            kwargs["organization"] = organization
        client = openai.OpenAI(**kwargs)

        # Paginate through all fine-tuning jobs (API returns max 100 per page)
        ft_after = None
        seen_cursors: set[str] = set()
        seen_jobs: set[str] = set()
        _ft_max_pages = 100  # safety guard: 10,000 jobs max
        for _ft_page in range(_ft_max_pages):
            ft_kwargs: dict = {"limit": 100}
            if ft_after:
                ft_kwargs["after"] = ft_after
            jobs = client.fine_tuning.jobs.list(**ft_kwargs)
            ft_page_data = getattr(jobs, "data", None)
            has_more = getattr(jobs, "has_more", None)
            if not isinstance(ft_page_data, list) or not isinstance(has_more, bool):
                warnings.append("openai:fine-tuning:malformed: Invalid inventory page; assessment incomplete.")
                break
            if not ft_page_data:
                if has_more:
                    warnings.append("openai:fine-tuning:malformed: Empty continuing page; assessment incomplete.")
                break
            for job in ft_page_data:
                job_id = getattr(job, "id", None)
                if not isinstance(job_id, str) or not job_id:
                    warnings.append("openai:fine-tuning:malformed: Missing job identity; assessment incomplete.")
                    continue
                if job_id in seen_jobs:
                    continue
                seen_jobs.add(job_id)
                try:
                    agent = _job_to_agent(job, organization)
                except (TypeError, ValueError, AttributeError):
                    warnings.append("openai:fine-tuning:malformed: Invalid job metadata; assessment incomplete.")
                    continue
                if agent is not None:
                    agents.append(agent)

            # Advance pagination cursor — strict bool check
            if not has_more:
                break
            cursor = getattr(ft_page_data[-1], "id", None)
            if not isinstance(cursor, str) or not cursor or cursor in seen_cursors:
                warnings.append("openai:fine-tuning:malformed: Missing or repeated pagination cursor; assessment incomplete.")
                break
            seen_cursors.add(cursor)
            ft_after = cursor
        else:
            warnings.append("openai:fine-tuning:incomplete: Pagination safety limit reached; assessment incomplete.")

    except Exception as exc:
        warnings.append(_read_failure(exc))

    return agents, warnings


def _job_to_agent(job: Any, organization: str | None) -> Agent | None:
    """Convert one validated job without discarding neighboring records."""
    job_id = job.id
    model = getattr(job, "model", "unknown")
    fine_tuned_model = getattr(job, "fine_tuned_model", None)
    status = getattr(job, "status", "unknown")
    training_file = getattr(job, "training_file", None) or ""

    # Only inventory completed fine-tunes
    if not fine_tuned_model:
        return None

    if (
        not isinstance(fine_tuned_model, str)
        or not isinstance(model, str)
        or not isinstance(status, str)
        or not isinstance(training_file, str)
    ):
        raise ValueError("Malformed fine-tuning metadata")

    packages = [Package(name="openai", version="unknown", ecosystem="pypi")]

    server = MCPServer(
        name=f"openai-ft:{fine_tuned_model}",
        transport=TransportType.UNKNOWN,
        packages=packages,
        env={"OPENAI_API_KEY": "***REDACTED***"},
        surface=ServerSurface.AI_INVENTORY,
    )

    # Add training file info as a tool descriptor
    if training_file:
        server.tools.append(
            MCPTool(
                name="training_data",
                description=f"Trained on file {training_file}, base model {model}",
            )
        )

    agent = Agent(
        name=f"openai-ft:{fine_tuned_model}",
        agent_type=AgentType.CUSTOM,
        config_path=f"openai://fine-tuning/{job_id}",
        source="openai-fine-tune",
        version=f"{status} (base: {model})",
        mcp_servers=[server],
        metadata={
            "cloud_origin": build_cloud_origin(
                provider="openai",
                service="fine-tuning",
                resource_type="job",
                resource_id=job_id,
                resource_name=fine_tuned_model,
                account_id=organization or None,
                raw_identity={
                    "id": job_id,
                    "model": model,
                    "fine_tuned_model": fine_tuned_model,
                    "status": status,
                    "training_file": training_file,
                },
            )
        },
    )
    return agent
