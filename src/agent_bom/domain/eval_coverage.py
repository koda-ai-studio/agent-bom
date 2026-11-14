"""Safety-eval coverage: a governance finding for risky agents no safety eval is linked to.

Thresholds (also in docs/AI_EVAL_COVERAGE.md):

* An agent is high-risk when the source scan shows at least one of
  - write/exec tools: a tool the existing capability classifier
    (:func:`agent_bom.risk_analyzer.classify_tool`) labels WRITE, DELETE,
    EXECUTE or ADMIN;
  - credentials: a credential env var the agent's file reads, other than the
    model-provider and tracing keys the agent uses to call its own model, or a
    tool labelled AUTH;
  - data access: a vector-store SDK the AI-component scan found in the agent's
    own file.
* Severity is a governance severity: ``medium`` with write/exec tools,
  otherwise ``low``. It never feeds the CVE counts or the vulnerability gate.
* A safety eval covers an agent when its purpose is ``safety`` and it is linked
  to the agent or to an agent that contains or delegates to it. Model-level and
  unlinked safety evals are reported as evidence but do not cover the agent.

The finding is raised only when eval detection ran to completion over the
project scope that holds the agent, and it states what was searched: it means
"no safety eval found in the scanned project files", never "never evaluated".
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from agent_bom.compliance_hub import apply_hub_classification
from agent_bom.finding import Asset, Finding, FindingSource, FindingType, stable_id
from agent_bom.risk_analyzer import ToolCapability, classify_tool

RULE_ID = "eval-coverage/safety-gap"
SEVERITY_WRITE_EXEC = "medium"
SEVERITY_OTHER_RISK = "low"
NIST_AI_RMF_CONTROLS = ["MEASURE-2.6", "MEASURE-2.7"]
_ACTING_CAPABILITIES = frozenset({ToolCapability.WRITE, ToolCapability.DELETE, ToolCapability.EXECUTE, ToolCapability.ADMIN})
# Keys an agent uses to call its own model or send traces; they grant no reach into other systems.
MODEL_PROVIDER_KEYS = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "AZURE_API_KEY",
        "COHERE_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GROQ_API_KEY",
        "MISTRAL_API_KEY",
        "OPENROUTER_API_KEY",
        "TOGETHER_API_KEY",
        "FIREWORKS_API_KEY",
        "DEEPSEEK_API_KEY",
        "XAI_API_KEY",
        "LANGSMITH_API_KEY",
        "LANGCHAIN_API_KEY",
        "LANGFUSE_SECRET_KEY",
        "LANGFUSE_PUBLIC_KEY",
    }
)
_MAX_EVIDENCE_SUITES = 20


@dataclass(frozen=True)
class RiskSignals:
    write_exec_tools: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    data_access: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str | None:
        if self.write_exec_tools:
            return SEVERITY_WRITE_EXEC
        if self.credentials or self.data_access:
            return SEVERITY_OTHER_RISK
        return None

    def to_dict(self) -> dict[str, list[str]]:
        return {"write_exec_tools": self.write_exec_tools, "credentials": self.credentials, "data_access": self.data_access}


def agent_risk_signals(agent: dict[str, Any], components: list[Any]) -> RiskSignals:
    """The high-risk capabilities the source scan recorded for one framework agent."""
    acting: set[str] = set()
    auth: set[str] = set()
    for capability in agent.get("capabilities") or []:
        name = str(capability.get("name") or "") if isinstance(capability, dict) else ""
        caps = set(classify_tool(name)) if name else set()
        if caps & _ACTING_CAPABILITIES:
            acting.add(name)
        if ToolCapability.AUTH in caps:
            auth.add(name)
    credentials = {str(ref) for ref in agent.get("credential_refs") or [] if str(ref) and str(ref).upper() not in MODEL_PROVIDER_KEYS}
    file_path = str(agent.get("file_path") or "")
    data = {
        str(comp.get("name") or "")
        for comp in components
        if isinstance(comp, dict) and comp.get("type") == "vector_store" and file_path and comp.get("file") == file_path
    }
    return RiskSignals(sorted(acting), sorted(credentials | auth), sorted(data - {""}))


def _relations(agents: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Agent → agents it contains or delegates to."""
    downstream: dict[str, set[str]] = {}
    for agent in agents:
        agent_id = str(agent.get("stable_id") or "")
        parent = str(agent.get("parent_id") or "")
        if parent and agent_id:
            downstream.setdefault(parent, set()).add(agent_id)
        for edge in agent.get("topology_edges") or []:
            if isinstance(edge, dict) and edge.get("kind") != "finish":
                source, target = str(edge.get("source_id") or ""), str(edge.get("target_id") or "")
                if source and target:
                    downstream.setdefault(source, set()).add(target)
    return downstream


def _covered(agents: list[dict[str, Any]], safety_suites: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Agent id → the linked safety suites that cover it directly or through a containing agent."""
    downstream = _relations(agents)
    covered: dict[str, list[dict[str, Any]]] = {}
    for suite in safety_suites:
        queue = deque(str(agent_id) for agent_id in suite.get("linked_agent_ids") or [])
        seen: set[str] = set()
        while queue:
            agent_id = queue.popleft()
            if agent_id in seen:
                continue
            seen.add(agent_id)
            covered.setdefault(agent_id, []).append(suite)
            queue.extend(downstream.get(agent_id, ()))
    return covered


def _suite_ref(suite: dict[str, Any]) -> dict[str, Any]:
    return {
        "stable_id": suite.get("stable_id"),
        "harness": suite.get("harness"),
        "name": suite.get("name"),
        "file_path": suite.get("file_path"),
        "purpose": suite.get("purpose"),
        "link_status": suite.get("link_status"),
        "results": list(suite.get("results") or []),
    }


def _scope_counts(suites: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"safety": 0, "quality": 0, "unknown": 0, "unlinked": 0}
    for suite in suites:
        purpose = str(suite.get("purpose") or "unknown")
        counts[purpose if purpose in counts else "unknown"] += 1
        counts["unlinked"] += suite.get("link_status") == "unlinked"
    return counts


def eval_coverage_findings(inventory: dict[str, Any] | None) -> list[Finding]:
    """Governance findings for high-risk framework agents with no linked safety eval."""
    if not isinstance(inventory, dict):
        return []
    coverage = inventory.get("eval_coverage")
    if not isinstance(coverage, dict) or coverage.get("status") != "complete":
        return []
    scopes = {str(scope) for scope in coverage.get("scopes") or []}
    agents = [agent for agent in inventory.get("framework_agents") or [] if isinstance(agent, dict) and agent.get("stable_id")]
    suites = [suite for suite in inventory.get("eval_suites") or [] if isinstance(suite, dict)]
    components = [comp for comp in inventory.get("components") or [] if isinstance(comp, dict)]
    safety = [suite for suite in suites if suite.get("purpose") == "safety"]
    covered = _covered(agents, safety)
    findings: list[Finding] = []
    for agent in agents:
        scope = str(agent.get("scope") or "")
        if scope not in scopes or str(agent["stable_id"]) in covered:
            continue
        signals = agent_risk_signals(agent, components)
        if signals.severity is None:
            continue
        in_scope = [suite for suite in suites if str(suite.get("scope") or "") == scope]
        findings.append(_finding(agent, signals, in_scope, coverage))
    return findings


def _finding(agent: dict[str, Any], signals: RiskSignals, suites: list[dict[str, Any]], coverage: dict[str, Any]) -> Finding:
    agent_id = str(agent["stable_id"])
    name = str(agent.get("name") or agent_id)
    scope = str(agent.get("scope") or "")
    file_path = str(agent.get("file_path") or "")
    models = {str(ref) for ref in agent.get("model_refs") or []}
    safety = [suite for suite in suites if suite.get("purpose") == "safety"]
    model_level = [_suite_ref(s) for s in safety if not s.get("linked_agent_ids") and models & set(s.get("linked_models") or [])]
    unlinked = [_suite_ref(s) for s in safety if s.get("link_status") == "unlinked"]
    linked = [_suite_ref(s) for s in suites if agent_id in (s.get("linked_agent_ids") or [])]
    reasons = [
        label
        for label, values in (
            ("write/exec tools", signals.write_exec_tools),
            ("credentials", signals.credentials),
            ("data access", signals.data_access),
        )
        if values
    ]
    description = (
        f"Agent '{name}' ({file_path}) has high-risk capabilities ({', '.join(reasons)}), and no safety or red-team eval "
        f"linked to this agent was found in the scanned project files (scope '{scope}', "
        f"{coverage.get('files_examined', 0)} candidate eval files read)."
    )
    if unlinked:
        description += f" {len(unlinked)} safety eval suite(s) in the project could not be linked to an agent."
    if model_level:
        description += " A safety eval targets this agent's model, which does not exercise the agent's tools."
    finding = Finding(
        finding_type=FindingType.EVAL_COVERAGE_GAP,
        source=FindingSource.EVAL_SCAN,
        asset=Asset(name=name, asset_type="agent", identifier=agent_id, location=file_path or None),
        severity=signals.severity or SEVERITY_OTHER_RISK,
        severity_source="rule",
        title=f"Agent '{name}' has high-risk capabilities and no linked safety eval",
        description=description,
        remediation_guidance=(
            "Add a safety or red-team eval that targets this agent and commit it with the project: for example a "
            "promptfoo config with a `redteam` section whose target is the agent's entry file (file://...), or a "
            "deepeval test that scores the agent's output with safety metrics. If a safety eval already exists, "
            "point its target at this agent so the scan can link it."
        ),
        nist_ai_rmf_tags=list(NIST_AI_RMF_CONTROLS),
        exposed_tools=list(signals.write_exec_tools),
        exposed_credentials=list(signals.credentials),
        affected_agents=[name],
        evidence={
            "rule_id": RULE_ID,
            "agent_id": agent_id,
            "framework": agent.get("framework", ""),
            "file": file_path,
            "line": agent.get("line_number", 0),
            "risk_signals": signals.to_dict(),
            "searched": {
                "scope": scope,
                "files_examined": coverage.get("files_examined", 0),
                "harnesses": list(coverage.get("harnesses") or []),
                "statement": "no safety eval found in the scanned project files",
            },
            "eval_suites_in_scope": _scope_counts(suites),
            "linked_evals": linked[:_MAX_EVIDENCE_SUITES],
            "model_level_safety_evals": model_level[:_MAX_EVIDENCE_SUITES],
            "unlinked_safety_evals": unlinked[:_MAX_EVIDENCE_SUITES],
        },
        id=stable_id("eval-coverage-gap", agent_id),
    )
    return apply_hub_classification(finding)
