"""`agent-bom gateway serve` — multi-MCP HTTP gateway CLI.

Fronts N upstream MCP servers through one URL, so laptop editors
(Cursor / VS Code / Claude / Codex / Copilot) point at one gateway
endpoint instead of configuring a proxy per MCP.

See docs/design/MULTI_MCP_GATEWAY.md.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

import click

from agent_bom.cli import _gateway_serve as _serve
from agent_bom.cli._gateway_upstream import upstream_options
from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.cli._runtime_status import emit_runtime_status_strip
from agent_bom.cli._server import _is_loopback_host
from agent_bom.cli._tenant import resolve_cli_tenant_id_strict
from agent_bom.runtime.injection_protection import INJECTION_MODE_HELP, INJECTION_MODES


def _parse_bind(bind: str) -> tuple[str, int]:
    host, sep, port_text = bind.rpartition(":")
    if not sep:
        raise click.UsageError("--bind must be in host:port form, for example 127.0.0.1:8090.")
    host = host or "0.0.0.0"  # nosec B104 - explicit gateway bind default
    try:
        port_num = int(port_text)
    except ValueError as exc:
        raise click.UsageError("--bind port must be an integer from 1 to 65535.") from exc
    if not 1 <= port_num <= 65535:
        raise click.UsageError("--bind port must be in range 1..65535.")
    return host, port_num


def _enforce_gateway_auth_defaults(host: str, bearer_token: str | None, allow_insecure_no_auth: bool) -> None:
    if bearer_token or _is_loopback_host(host):
        return
    try:
        from agent_bom.api.auth import get_key_store

        if get_key_store().has_keys():
            return
    except Exception:
        # App construction performs the fail-closed check and reports
        # authentication backend startup errors without falling open.
        return
    if allow_insecure_no_auth:
        return
    raise click.ClickException(
        f"Refusing to expose `gateway serve` on non-loopback host {host!r} without incoming authentication. "
        "Set --bearer-token / AGENT_BOM_GATEWAY_BEARER_TOKEN, configure gateway API keys, "
        "or pass --allow-insecure-no-auth to override."
    )


@click.group(cls=SuggestingGroup, help="Multi-MCP gateway commands.")
def gateway_group() -> None:
    """Entry point for gateway subcommands."""


@gateway_group.command("init-policy")
@click.option(
    "--template",
    "template_name",
    type=click.Choice(["baseline", "self-governance"], case_sensitive=False),
    default="baseline",
    show_default=True,
    help="Render the general baseline or the agent-bom operator self-governance policy.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("gateway-baseline-policy.json"),
    show_default=True,
    help="Output path for the rendered gateway baseline policy.",
)
@click.option(
    "--mode",
    type=click.Choice(["audit", "enforce"], case_sensitive=False),
    default="audit",
    show_default=True,
    help="Policy rollout mode. Audit renders advisory rules; enforce renders blocking rules.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["proxy", "control-plane"], case_sensitive=False),
    default="proxy",
    show_default=True,
    help="Render for local `gateway serve --policy` or for control-plane policy import.",
)
@click.option("--tenant-id", default="default", show_default=True, help="Tenant id embedded in control-plane policy output.")
def init_policy_cmd(template_name: str, output_path: Path, mode: str, output_format: str, tenant_id: str) -> None:
    """Render the bundled secure-by-default gateway baseline policy."""
    from agent_bom.gateway_policy_templates import (
        GatewayBaselineFormat,
        GatewayBaselineMode,
        render_gateway_baseline_policy,
        render_self_governance_policy,
    )
    from agent_bom.proxy_policy import summarize_policy_bundle

    mode_value = cast(GatewayBaselineMode, mode.lower())
    format_value = cast(GatewayBaselineFormat, output_format.lower())
    renderer = render_self_governance_policy if template_name.lower() == "self-governance" else render_gateway_baseline_policy
    rendered = renderer(
        mode=mode_value,
        output_format=format_value,
        tenant_id=tenant_id,
    )
    output_path.write_text(json.dumps(rendered, indent=2) + "\n", encoding="utf-8")

    if output_format.lower() == "proxy":
        summary = summarize_policy_bundle(rendered)
        click.echo(f"Gateway {template_name.lower()} policy written to {output_path}")
        click.echo(f"Use it with: agent-bom gateway serve --policy {output_path} --upstreams <upstreams.yaml>")
        click.echo(
            f"Mode={mode.lower()} rules={summary['total_rules']} blocks={summary['blocking_rules']} warnings={summary['advisory_rules']}"
        )
    else:
        click.echo(f"Gateway {template_name.lower()} control-plane policy written to {output_path}")


@gateway_group.command("serve")
@upstream_options
@click.option(
    "--upstreams",
    "upstreams_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "YAML file listing upstream MCP servers (see "
        "docs/design/MULTI_MCP_GATEWAY.md). When --from-control-plane is also "
        "set, entries here overlay on top of discovered upstreams — use to "
        "attach bearer-token auth to a discovered upstream."
    ),
)
@click.option(
    "--from-control-plane",
    "control_plane_url",
    default=None,
    help=(
        "Pull auto-discovered upstreams from this agent-bom control plane URL "
        "(hits /v1/gateway/upstreams/discovered). Fleet scans surface remote "
        "streamable HTTP MCPs into this endpoint — the gateway registers whatever the "
        "fleet has discovered, so pilot teams don't start from a blank YAML."
    ),
)
@click.option(
    "--control-plane-token",
    "control_plane_token",
    envvar="AGENT_BOM_CONTROL_PLANE_TOKEN",
    default=None,
    help="Bearer token for the control plane API key (or set AGENT_BOM_CONTROL_PLANE_TOKEN).",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional runtime policy JSON file (same format as `agent-bom proxy --policy`).",
)
@click.option(
    "--policy-reload-seconds",
    type=int,
    envvar="AGENT_BOM_GATEWAY_POLICY_RELOAD_SECONDS",
    default=0,
    show_default=True,
    help="Reload the gateway policy JSON file in-process on this interval (0 disables hot reload).",
)
@click.option(
    "--policy-bundle",
    "policy_bundle_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Control-plane GatewayPolicy bundle JSON (a list of policies, or "
        "{'policies': [...]}). Unlike --policy, these are enforced per "
        "source_agent via bound_agents/bound_agent_types/bound_environments, "
        "matching the per-MCP proxy. Export from the control plane's "
        "/v1/gateway/policies."
    ),
)
@click.option(
    "--firewall-policy",
    "firewall_policy_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=("Inter-agent firewall policy JSON file (#982). Schema: see `agent-bom firewall validate --help` and docs/AGENT_FIREWALL.md."),
)
@click.option(
    "--firewall-policy-reload-seconds",
    type=int,
    envvar="AGENT_BOM_GATEWAY_FIREWALL_POLICY_RELOAD_SECONDS",
    default=0,
    show_default=True,
    help="Hot-reload the firewall policy JSON file on this interval (0 disables).",
)
@click.option("--bind", default="0.0.0.0:8090", show_default=True, help="Bind address host:port.")
@click.option(
    "--runtime-rate-limit-per-tenant-per-minute",
    type=int,
    envvar="AGENT_BOM_GATEWAY_RATE_LIMIT_PER_TENANT_PER_MINUTE",
    default=0,
    show_default=True,
    help="Tenant-scoped runtime request limit for gateway relay traffic (0 disables).",
)
@click.option(
    "--require-shared-rate-limit",
    is_flag=True,
    envvar="AGENT_BOM_GATEWAY_REQUIRE_SHARED_RATE_LIMIT",
    default=False,
    help="Fail closed unless gateway runtime rate limiting uses a shared backend.",
)
@click.option(
    "--bearer-token",
    envvar="AGENT_BOM_GATEWAY_BEARER_TOKEN",
    default=None,
    help="Require incoming bearer/API-key auth for gateway clients.",
)
@click.option(
    "--bearer-token-expires-at",
    envvar="AGENT_BOM_GATEWAY_BEARER_TOKEN_EXPIRES_AT",
    default=None,
    help="Required with --bearer-token: absolute timezone-aware ISO-8601 expiry in the next hour.",
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help="Allow unauthenticated non-loopback gateway exposure. Unsafe outside local development.",
)
@click.option(
    "--allow-anonymous-agents",
    is_flag=True,
    envvar="AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS",
    default=False,
    help=(
        "Allow callers without an agent_identity token to relay on a non-loopback listener. "
        "Invalid/revoked tokens are always denied. Unsafe outside local development."
    ),
)
@click.option(
    "--profile-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_PROFILE_ENFORCEMENT",
    default="off",
    show_default=True,
    help="Resolve canonical managed client profiles before routing; enforce denies unsanctioned callers, warn audits them.",
)
@click.option(
    "--profile-environment",
    envvar="AGENT_BOM_GATEWAY_PROFILE_ENVIRONMENT",
    default="",
    help="Operator-controlled deployment environment matched against canonical client profiles.",
)
@click.option(
    "--profile-issuer",
    envvar="AGENT_BOM_GATEWAY_PROFILE_ISSUER",
    default="agent-bom",
    show_default=True,
    help="Trusted issuer required by canonical client profiles.",
)
@click.option(
    "--allow-profile-dev-bypass",
    is_flag=True,
    envvar="AGENT_BOM_GATEWAY_ALLOW_PROFILE_DEV_BYPASS",
    default=False,
    help="Allow unresolved profiles only on a loopback listener and emit an audited development bypass.",
)
@click.option(
    "--detect-visual-leaks",
    is_flag=True,
    envvar="AGENT_BOM_GATEWAY_DETECT_VISUAL_LEAKS",
    default=False,
    help="OCR-scan image tool responses for credentials/PII (requires 'agent-bom[visual]').",
)
@click.option(
    "--drift-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_DRIFT_ENFORCEMENT",
    default="off",
    show_default=True,
    help="Act on open behavioral-drift incidents: 'enforce' blocks out-of-blueprint tools, 'warn' audits them, 'off' stays advisory.",
)
@click.option(
    "--anomaly-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_ANOMALY_ENFORCEMENT",
    default="off",
    show_default=True,
    help="Act on cost-spike anomalies: 'enforce' blocks a runaway agent, 'warn' audits it, 'off' stays advisory.",
)
@click.option(
    "--fleet-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_FLEET_ENFORCEMENT",
    default="enforce",
    show_default=True,
    help=(
        "Act on quarantined fleet agents: 'enforce' blocks every call from a quarantined agent, "
        "'warn' audits it, 'off' stays advisory. Defaults to 'enforce' so quarantine actually "
        "contains on this relay; the check fails open if the fleet store is unreachable."
    ),
)
@click.option(
    "--graph-reachability-report",
    "graph_reachability_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="AGENT_BOM_GATEWAY_GRAPH_REACHABILITY_REPORT",
    default=None,
    help=(
        "Scan-report JSON whose AGENT_REACHES_PRIVILEGED graph findings supply "
        "agent→privileged-node reachability facts. With --graph-reachability-enforcement "
        "warn/enforce, an over-reaching agent's first call to one of its reachable "
        "privileged tools is flagged/blocked pre-emptively (consume direction). "
        "Read-only; a missing/malformed report is a no-op."
    ),
)
@click.option(
    "--graph-reachability-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_GRAPH_REACHABILITY_ENFORCEMENT",
    default="off",
    show_default=True,
    help=(
        "Act on graph-derived agent→privileged-node reachability: 'enforce' blocks "
        "the first reaching call, 'warn' audits it, 'off' stays advisory."
    ),
)
@click.option(
    "--graph-reachability-bundle-url",
    envvar="AGENT_BOM_GATEWAY_GRAPH_REACHABILITY_BUNDLE_URL",
    default="",
    help="Authenticated runtime-facts endpoint for a completed graph correlation.",
)
@click.option(
    "--graph-reachability-bundle-tenant",
    envvar="AGENT_BOM_GATEWAY_GRAPH_REACHABILITY_BUNDLE_TENANT",
    default="default",
    show_default=True,
    help="Tenant identity that the signed runtime-facts bundle must match.",
)
@click.option(
    "--graph-reachability-bundle-signing-key-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="AGENT_BOM_GATEWAY_GRAPH_REACHABILITY_BUNDLE_SIGNING_KEY_FILE",
    default=None,
    help="File containing the HMAC verification key for signed runtime facts.",
)
@click.option(
    "--graph-reachability-bundle-poll-seconds",
    type=float,
    envvar="AGENT_BOM_GATEWAY_GRAPH_REACHABILITY_BUNDLE_POLL_SECONDS",
    default=30.0,
    show_default=True,
    help="Polling interval for signed runtime facts; 0 loads once at startup.",
)
@click.option(
    "--graph-reachability-failure-mode",
    type=click.Choice(["allow", "deny"]),
    envvar="AGENT_BOM_GATEWAY_GRAPH_REACHABILITY_FAILURE_MODE",
    default="allow",
    show_default=True,
    help="Behavior when configured graph evidence is unavailable; deny is strict opt-in.",
)
@click.option(
    "--enable-oauth-as",
    is_flag=True,
    envvar="AGENT_BOM_GATEWAY_ENABLE_OAUTH_AS",
    default=False,
    help=("Unavailable: fails startup until trusted client authorization is implemented. Use configured bearer or API-key authentication."),
)
@click.option(
    "--oauth-as-issuer",
    envvar="AGENT_BOM_GATEWAY_OAUTH_AS_ISSUER",
    default=None,
    hidden=True,
    expose_value=False,
    deprecated="ignored; the embedded OAuth AS is unavailable and the gateway reads no issuer from this option",
)
@click.option(
    "--a2a-mutual-auth-enforcement",
    type=click.Choice(["off", "warn", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_A2A_MUTUAL_AUTH_ENFORCEMENT",
    default="off",
    show_default=True,
    help="Inline A2A mutual-auth: 'enforce' rejects unauthenticated/unverified inter-agent edges, 'warn' audits them.",
)
@click.option(
    "--tool-scope-map",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="AGENT_BOM_GATEWAY_TOOL_SCOPE_MAP",
    default=None,
    help='JSON file mapping tool names to required OAuth scopes, e.g. {"fs.write": ["tools:write"]}. "*" applies to all tools.',
)
@click.option(
    "--enable-dlp",
    is_flag=True,
    envvar="AGENT_BOM_GATEWAY_ENABLE_DLP",
    default=False,
    help=(
        "Run a DLP pass on tool-call arguments and results "
        "(injection/PII/secrets/payload-vuln). OFF by default: without this flag "
        "the gateway does NOT scan, redact, or block secrets or PII. Pair with "
        "--dlp-mode enforce to actually block/redact."
    ),
)
@click.option(
    "--dlp-mode",
    type=click.Choice(["audit", "enforce"]),
    envvar="AGENT_BOM_GATEWAY_DLP_MODE",
    default="audit",
    show_default=True,
    help="DLP posture: 'enforce' blocks/redacts sensitive content, 'audit' only flags it.",
)
@click.option(
    "--dlp-pii-action",
    type=click.Choice(["redact", "block"]),
    envvar="AGENT_BOM_GATEWAY_DLP_PII_ACTION",
    default="redact",
    show_default=True,
    help="How DLP handles PII matches in enforce mode.",
)
@click.option("--injection-mode", type=click.Choice(INJECTION_MODES), envvar="AGENT_BOM_GATEWAY_INJECTION_MODE", help=INJECTION_MODE_HELP)
@click.option(
    "--allow-visual-leak-best-effort",
    is_flag=True,
    default=False,
    help="Continue startup if visual leak detection is enabled but OCR runtime support is unavailable.",
)
@click.option(
    "--log-level", type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False), default="info", show_default=True
)
def serve_cmd(
    upstream_options: dict[str, Any],
    upstreams_path: Path | None,
    control_plane_url: str | None,
    control_plane_token: str | None,
    policy_path: Path | None,
    policy_reload_seconds: int,
    policy_bundle_path: Path | None,
    firewall_policy_path: Path | None,
    firewall_policy_reload_seconds: int,
    bind: str,
    runtime_rate_limit_per_tenant_per_minute: int,
    require_shared_rate_limit: bool,
    bearer_token: str | None,
    bearer_token_expires_at: str | None,
    allow_insecure_no_auth: bool,
    allow_anonymous_agents: bool,
    profile_enforcement: str,
    profile_environment: str,
    profile_issuer: str,
    allow_profile_dev_bypass: bool,
    detect_visual_leaks: bool,
    drift_enforcement: str,
    anomaly_enforcement: str,
    fleet_enforcement: str,
    graph_reachability_path: Path | None,
    graph_reachability_enforcement: str,
    graph_reachability_bundle_url: str,
    graph_reachability_bundle_tenant: str,
    graph_reachability_bundle_signing_key_file: Path | None,
    graph_reachability_bundle_poll_seconds: float,
    graph_reachability_failure_mode: str,
    enable_oauth_as: bool,
    a2a_mutual_auth_enforcement: str,
    tool_scope_map: Path | None,
    enable_dlp: bool,
    dlp_mode: str,
    dlp_pii_action: str,
    injection_mode: str | None,
    allow_visual_leak_best_effort: bool,
    log_level: str,
) -> None:
    """Run the gateway server on ``bind``.

    Upstreams come from (a) ``--from-control-plane`` auto-discovery, (b)
    a local ``--upstreams`` YAML, or both (YAML overlays on top of
    discovery). Must provide at least one — an empty gateway serves
    nothing.
    """
    logging.basicConfig(level=log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")

    uvicorn = _serve.require_serve_prerequisites(enable_oauth_as, upstreams_path, control_plane_url)

    host, port_num = _parse_bind(bind)
    graph_reachability_bundle_signing_key = _serve.validate_profile_and_graph_options(
        host,
        profile_enforcement=profile_enforcement,
        profile_environment=profile_environment,
        profile_issuer=profile_issuer,
        allow_profile_dev_bypass=allow_profile_dev_bypass,
        bundle_poll_seconds=graph_reachability_bundle_poll_seconds,
        bundle_url=graph_reachability_bundle_url,
        bundle_tenant=graph_reachability_bundle_tenant,
        bundle_signing_key_file=graph_reachability_bundle_signing_key_file,
    )

    from agent_bom.gateway_server import GatewaySettings, build_control_plane_audit_sink, create_gateway_app

    _serve.validate_bearer_token_expiry(bearer_token, bearer_token_expires_at)
    registry = _serve.load_upstream_registry(control_plane_url, control_plane_token, upstreams_path)
    policy = _serve.load_runtime_policies(policy_path, policy_reload_seconds, firewall_policy_path, firewall_policy_reload_seconds)

    _enforce_gateway_auth_defaults(host, bearer_token, allow_insecure_no_auth)
    _serve.require_visual_leak_runtime(detect_visual_leaks, allow_visual_leak_best_effort)

    audit_sink = None
    if control_plane_url:
        audit_sink = build_control_plane_audit_sink(
            control_plane_url, control_plane_token, tenant_id=resolve_cli_tenant_id_strict(), source_id="gateway"
        )
    control_plane_policies = _serve.load_policy_bundle(policy_bundle_path)
    oidc_discovery_shim = _serve.load_oidc_discovery_shim()
    tool_scope_mapping = _serve.load_tool_scope_map(tool_scope_map)

    settings = GatewaySettings(
        **upstream_options,
        registry=registry,
        policy=policy,
        audit_sink=audit_sink,
        control_plane_policies=control_plane_policies,
        bearer_token=bearer_token,
        bearer_token_expires_at=bearer_token_expires_at,
        enable_visual_leak_detection=detect_visual_leaks,
        require_visual_leak_detection_ready=detect_visual_leaks and not allow_visual_leak_best_effort,
        runtime_rate_limit_per_tenant_per_minute=max(runtime_rate_limit_per_tenant_per_minute, 0),
        require_shared_rate_limit=require_shared_rate_limit,
        policy_path=policy_path,
        policy_reload_interval_seconds=max(policy_reload_seconds, 0),
        firewall_policy_path=firewall_policy_path,
        firewall_policy_reload_interval_seconds=max(firewall_policy_reload_seconds, 0),
        listener_host=host,
        allow_insecure_no_auth=allow_insecure_no_auth,
        allow_anonymous_agents=allow_anonymous_agents,
        runtime_profile_enforcement_mode=profile_enforcement,
        runtime_profile_environment=profile_environment.strip(),
        runtime_profile_issuer=profile_issuer.strip(),
        allow_runtime_profile_dev_bypass=allow_profile_dev_bypass,
        drift_enforcement_mode=drift_enforcement,
        anomaly_enforcement_mode=anomaly_enforcement,
        fleet_enforcement_mode=fleet_enforcement,
        graph_reachability_path=graph_reachability_path,
        graph_reachability_enforcement_mode=graph_reachability_enforcement,
        graph_reachability_failure_mode=graph_reachability_failure_mode,
        graph_reachability_bundle_url=graph_reachability_bundle_url.strip(),
        graph_reachability_bundle_tenant_id=graph_reachability_bundle_tenant.strip(),
        graph_reachability_bundle_signing_key=graph_reachability_bundle_signing_key,
        graph_reachability_bundle_bearer_token=control_plane_token or "",
        graph_reachability_bundle_poll_interval_seconds=graph_reachability_bundle_poll_seconds,
        oauth_as=None,
        oidc_discovery_shim=oidc_discovery_shim,
        a2a_mutual_auth_enforcement_mode=a2a_mutual_auth_enforcement,
        tool_scope_map=tool_scope_mapping,
        dlp_enabled=enable_dlp,
        dlp_mode=dlp_mode,
        dlp_pii_action=dlp_pii_action,
        injection_mode=injection_mode or "alert",
    )
    app = create_gateway_app(settings)

    _serve.emit_startup_summary(
        bind_url=f"http://{host}:{port_num}",
        registry=registry,
        policy=policy,
        bearer_token=bearer_token,
        allow_insecure_no_auth=allow_insecure_no_auth,
        profile_enforcement=profile_enforcement,
        profile_environment=profile_environment,
        profile_issuer=profile_issuer,
        detect_visual_leaks=detect_visual_leaks,
        allow_visual_leak_best_effort=allow_visual_leak_best_effort,
        policy_path=policy_path,
        policy_reload_seconds=policy_reload_seconds,
        firewall_policy_path=firewall_policy_path,
        firewall_policy_reload_seconds=firewall_policy_reload_seconds,
    )
    emit_runtime_status_strip("gateway", calls=0, blocked=0, last_decision="listening")
    uvicorn.run(app, host=host, port=port_num, log_level=log_level.lower(), proxy_headers=False)


__all__ = ["gateway_group", "init_policy_cmd", "serve_cmd"]
