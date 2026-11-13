"""Static index of top-level commands: where each loads from and its help line.

Top-level ``--help`` and typo suggestions read this table so they never import
a command module. ``tests/test_cli_lazy_commands.py`` checks every entry against
the real command, so a changed docstring fails with the exact text to paste here.
"""

from __future__ import annotations

from typing import NamedTuple


class CommandEntry(NamedTuple):
    loader: str
    short_help: str
    hidden: bool = False


COMMAND_INDEX: dict[str, CommandEntry] = {
    "activity": CommandEntry("agent_bom.cli._activity:activity_cmd", "Review what Claude Code and Codex did: MCP..."),
    "agents": CommandEntry(
        "agent_bom.cli._command_loaders:load_agents_alias", "Discover agents, extract dependencies, scan...", hidden=True
    ),
    "api": CommandEntry("agent_bom.cli._command_loaders:load_api", "Start the agent-bom REST API server.", hidden=True),
    "attest": CommandEntry("agent_bom.cli._attest_group:attest_group", "Sign and verify SBOM and MCP scan..."),
    "audit": CommandEntry("agent_bom.cli._runtime:audit_replay_cmd", "View and analyse a proxy audit JSONL log."),
    "audit-drain-dlq": CommandEntry("agent_bom.cli._runtime:audit_drain_dlq_cmd", "Drain valid proxy audit DLQ records into a..."),
    "auth": CommandEntry("agent_bom.cli._auth_group:auth_group", "Authentication setup helpers — guided SSO /..."),
    "campaigns": CommandEntry("agent_bom.cli._campaigns_group:campaigns_cmd", "Assign, ticket, verify, and inspect..."),
    "capabilities": CommandEntry("agent_bom.cli._capabilities:capabilities_cmd", "Show every gated capability: state, why, and..."),
    "check": CommandEntry("agent_bom.cli._check:check", "Check a package for known vulnerabilities..."),
    "cloud": CommandEntry("agent_bom.cli.cloud:cloud_group", "Scan cloud infrastructure — AWS, Azure, GCP."),
    "code": CommandEntry("agent_bom.cli._focused_commands:code_cmd", "Run native AST and AI-component analysis —..."),
    "completions": CommandEntry("agent_bom.cli._inventory:completions_cmd", "Print shell completion script."),
    "compliance": CommandEntry("agent_bom.cli._compliance_group:compliance_cmd", "Run framework compliance evaluations from the..."),
    "connect": CommandEntry("agent_bom.cli._command_loaders:load_connect", "Read-only onboard a cloud or data source —..."),
    "cost": CommandEntry("agent_bom.cli._cost_group:cost_group", "LLM FinOps — spend forecast and chargeback..."),
    "db": CommandEntry("agent_bom.cli._db:db_cmd", "Manage the local vulnerability database."),
    "demo": CommandEntry("agent_bom.cli._demo:demo_group", "Inspect the bundled, explicitly synthetic..."),
    "doctor": CommandEntry("agent_bom.cli._doctor:doctor_cmd", "Check environment readiness for scanning."),
    "export": CommandEntry("agent_bom.cli._exports_group:export_cmd", "Manage connect-once findings-export..."),
    "findings": CommandEntry("agent_bom.cli._findings_group:findings_cmd", "Inspect and triage normalized findings from..."),
    "firewall": CommandEntry("agent_bom.cli._firewall:firewall_group", "Inter-agent firewall policy tooling."),
    "fleet": CommandEntry("agent_bom.cli.claw:fleet_group", "Manage AI agent fleet — discovery, lifecycle,..."),
    "fs": CommandEntry("agent_bom.cli._focused_commands:fs_cmd", "Scan a filesystem directory or mounted VM..."),
    "gateway": CommandEntry("agent_bom.cli._gateway:gateway_group", "Multi-MCP gateway commands."),
    "graph": CommandEntry("agent_bom.cli._analysis:graph_cmd", "Export the transitive dependency graph from a..."),
    "graph-correlate": CommandEntry(
        "agent_bom.cli._graph_correlate_group:graph_correlate_cmd", "Correlate immutable scan snapshots into one..."
    ),
    "graph-evidence": CommandEntry("agent_bom.cli._analysis:graph_evidence_cmd", "Export retained graph history or a..."),
    "graph-paths": CommandEntry("agent_bom.cli._graph_paths_group:graph_paths_cmd", "Query ranked attack paths and exposure paths..."),
    "guard": CommandEntry("agent_bom.cli._command_loaders:load_guard", "Pre-install security guard — scan packages...", hidden=True),
    "iac": CommandEntry("agent_bom.cli._focused_commands:iac_cmd", "Scan infrastructure-as-code files for..."),
    "identity": CommandEntry("agent_bom.cli._identity_group:identity_group", "Non-human identity governance — credentials,..."),
    "image": CommandEntry("agent_bom.cli._focused_commands:image_cmd", "Scan a container image for vulnerabilities."),
    "ingest": CommandEntry("agent_bom.cli._ingest_group:ingest_group", "Ingest operator-provided evidence into the..."),
    "interactive": CommandEntry("agent_bom.cli._interactive:interactive_cmd", "Start an interactive command shell."),
    "manifest": CommandEntry("agent_bom.cli._agent_manifest:manifest_cmd", "Emit the canonical Agent BOM manifest for..."),
    "mcp": CommandEntry("agent_bom.cli._command_loaders:load_mcp", "Discover, scan, and manage MCP agents and..."),
    "mcp-server": CommandEntry("agent_bom.cli._command_loaders:load_mcp_server_alias", "Start agent-bom as an MCP server.", hidden=True),
    "mesh": CommandEntry("agent_bom.cli._analysis:mesh_cmd", "Show lightweight agent/MCP topology without..."),
    "plugins": CommandEntry("agent_bom.cli._plugins:plugins_group", "Inspect extension plugin entry-point..."),
    "policy": CommandEntry("agent_bom.cli._command_loaders:load_policy", "Policy management — install guards,..."),
    "policy-templates": CommandEntry(
        "agent_bom.cli._command_loaders:load_policy_templates_alias", "Generate a starter policy file with common...", hidden=True
    ),
    "profiles": CommandEntry("agent_bom.cli._profiles:profiles_group", "Manage named CLI profiles in..."),
    "proxy": CommandEntry("agent_bom.cli._runtime:proxy_cmd", "Run an MCP server through agent-bom's..."),
    "proxy-bootstrap": CommandEntry("agent_bom.cli._runtime:proxy_bootstrap_cmd", "Generate managed endpoint onboarding..."),
    "quickstart": CommandEntry("agent_bom.cli._quickstart:quickstart_cmd", "Print — or with --run, execute — a local..."),
    "registry": CommandEntry("agent_bom.cli._command_loaders:load_registry", "Manage the MCP server registry.", hidden=True),
    "remediate": CommandEntry("agent_bom.cli._verify_remediation:remediate_cmd", "Generate a prioritized remediation plan for..."),
    "report": CommandEntry("agent_bom.cli._command_loaders:load_report", "Reports — history, diff, analytics, and..."),
    "run": CommandEntry("agent_bom.cli._command_loaders:load_run", "Launch SERVER through agent-bom's runtime proxy.", hidden=True),
    "runtime": CommandEntry("agent_bom.cli._command_loaders:load_runtime", "Runtime enforcement, managed profiles and..."),
    "samples": CommandEntry("agent_bom.cli._samples:samples_group", "Create bundled sample inputs for demos and..."),
    "sbom": CommandEntry("agent_bom.cli._focused_commands:sbom_cmd", "Ingest an existing SBOM (CycloneDX/SPDX) and..."),
    "scan": CommandEntry("agent_bom.cli.agents.scan_cmd:scan", "Discover agents, extract dependencies, scan..."),
    "scanners": CommandEntry("agent_bom.cli._scanner_registry:scanners_cmd", "List scanner drivers, capabilities, and..."),
    "schedule": CommandEntry("agent_bom.cli._registry:schedule", "Manage recurring scan schedules."),
    "secrets": CommandEntry("agent_bom.cli._focused_commands:secrets_cmd", "Scan a directory for hardcoded secrets and PII."),
    "self-audit": CommandEntry("agent_bom.cli._self_audit:self_audit_cmd", "Audit THIS agent-bom deployment's own..."),
    "serve": CommandEntry("agent_bom.cli._server:serve_cmd", "Start the API server and serve the dashboard..."),
    "sidecar-injector": CommandEntry("agent_bom.cli._deploy:sidecar_injector_cmd", "Run the TLS admission webhook that..."),
    "skills": CommandEntry("agent_bom.cli._skills_group:skills_group", "Scan, verify, and rescan AI instruction..."),
    "teardown": CommandEntry("agent_bom.cli._deploy:teardown_cmd", "Tear down the AWS/EKS reference install owned..."),
    "ticket": CommandEntry("agent_bom.cli._ticketing_group:ticket_cmd", "File and sync ITSM tickets for findings..."),
    "trust": CommandEntry("agent_bom.cli._trust:trust_cmd", "Show data access, network, auth, and storage..."),
    "up": CommandEntry("agent_bom.cli._command_loaders:load_up", "Run the platform locally (alias of `serve`)."),
    "update": CommandEntry("agent_bom.cli._upgrade:update_cmd", "Disambiguate the ambiguous `update` verb...", hidden=True),
    "upgrade": CommandEntry("agent_bom.cli._upgrade:upgrade_cmd", "Check for and install the latest version of..."),
    "validate": CommandEntry(
        "agent_bom.cli._command_loaders:load_validate_alias", "Validate an inventory file against the...", hidden=True
    ),
    "verify": CommandEntry("agent_bom.cli._check:verify", "Verify package integrity and provenance..."),
    "verify-remediation": CommandEntry(
        "agent_bom.cli._verify_remediation:verify_remediation", "Capture and compare installed Python metadata..."
    ),
    "watch": CommandEntry("agent_bom.cli._runtime:watch_cmd", "Watch MCP configs for changes and alert on..."),
    "where": CommandEntry("agent_bom.cli._inventory:where", "Show where agent-bom looks for MCP..."),
}
