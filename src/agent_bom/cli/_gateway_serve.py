"""Startup validation and input loading for `agent-bom gateway serve`.

Each helper owns one input family and fails the same way the command always
has: ``click.ClickException`` for invalid configuration, exit status 2 for
missing or unusable upstream sources.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from agent_bom.cli._common import read_json_file_for_cli
from agent_bom.cli._server import _is_loopback_host


def require_serve_prerequisites(enable_oauth_as: bool, upstreams_path: Path | None, control_plane_url: str | None) -> Any:
    """Refuse the unavailable OAuth AS and an empty upstream set; return the uvicorn module."""
    if enable_oauth_as:
        raise click.ClickException(
            "Embedded OAuth AS is unavailable until trusted client authorization is implemented. "
            "Remove --enable-oauth-as / AGENT_BOM_GATEWAY_ENABLE_OAUTH_AS and configure bearer or API-key authentication."
        )

    if upstreams_path is None and control_plane_url is None:
        click.echo("error: pass --upstreams or --from-control-plane (or both). See `agent-bom gateway serve --help`.", err=True)
        sys.exit(2)

    try:
        import uvicorn
    except ImportError:
        click.echo(
            "The gateway requires the 'api' extra — install with `pip install 'agent-bom[api]'`",
            err=True,
        )
        sys.exit(2)
    return uvicorn


def validate_profile_and_graph_options(
    host: str,
    *,
    profile_enforcement: str,
    profile_environment: str,
    profile_issuer: str,
    allow_profile_dev_bypass: bool,
    bundle_poll_seconds: float,
    bundle_url: str,
    bundle_tenant: str,
    bundle_signing_key_file: Path | None,
) -> bytes | None:
    """Reject inconsistent client-profile / runtime-facts options; return the bundle signing key."""
    if profile_enforcement != "off" and not profile_environment.strip():
        raise click.ClickException("--profile-enforcement warn/enforce requires --profile-environment")
    if profile_enforcement != "off" and not profile_issuer.strip():
        raise click.ClickException("--profile-enforcement warn/enforce requires --profile-issuer")
    if allow_profile_dev_bypass and not _is_loopback_host(host):
        raise click.ClickException("--allow-profile-dev-bypass is permitted only with a loopback --bind")
    if bundle_poll_seconds < 0:
        raise click.ClickException("--graph-reachability-bundle-poll-seconds must be >= 0")
    if bundle_url and bundle_signing_key_file is None:
        raise click.ClickException("--graph-reachability-bundle-url requires --graph-reachability-bundle-signing-key-file")
    if bundle_url and not bundle_tenant.strip():
        raise click.ClickException("--graph-reachability-bundle-url requires a non-empty bundle tenant")
    if bundle_signing_key_file is None:
        return None
    try:
        signing_key = bundle_signing_key_file.read_bytes().strip()
    except OSError as exc:
        raise click.ClickException("unable to read graph reachability bundle signing key") from exc
    if len(signing_key) < 32:
        raise click.ClickException("graph reachability bundle signing key must contain at least 32 bytes")
    return signing_key


def validate_bearer_token_expiry(bearer_token: str | None, bearer_token_expires_at: str | None) -> None:
    if not bearer_token:
        return
    from agent_bom.gateway_server import _parse_gateway_token_expiry

    try:
        _parse_gateway_token_expiry(bearer_token_expires_at)
    except ValueError as exc:
        raise click.ClickException(
            "--bearer-token-expires-at / AGENT_BOM_GATEWAY_BEARER_TOKEN_EXPIRES_AT must be a timezone-aware "
            "ISO-8601 expiry in the next hour"
        ) from exc


def load_upstream_registry(control_plane_url: str | None, control_plane_token: str | None, upstreams_path: Path | None) -> Any:
    """Control-plane discovery first, then the local YAML overlaid on top."""
    from agent_bom.gateway_upstreams import (
        UpstreamConfigError,
        UpstreamRegistry,
        fetch_discovered_upstreams,
    )

    registry: UpstreamRegistry | None = None

    if control_plane_url is not None:
        try:
            payload = fetch_discovered_upstreams(control_plane_url, token=control_plane_token)
            discovered = UpstreamRegistry.from_discovery_response(payload)
            click.echo(f"discovered {len(discovered)} upstream(s) from {control_plane_url}: {', '.join(discovered.names()) or '(none)'}")
            registry = discovered
        except Exception as exc:  # noqa: BLE001 — network/DNS/permission all surface here
            click.echo(f"control-plane discovery failed: {exc}", err=True)
            if upstreams_path is None:
                sys.exit(2)
            click.echo("continuing with local --upstreams only", err=True)

    if upstreams_path is not None:
        try:
            local = UpstreamRegistry.from_yaml(upstreams_path)
        except UpstreamConfigError as exc:
            click.echo(f"upstreams config error: {exc}", err=True)
            sys.exit(2)
        registry = local if registry is None else registry.merged_with(local)

    assert registry is not None  # callers require --upstreams or --from-control-plane
    return registry


def load_runtime_policies(
    policy_path: Path | None,
    policy_reload_seconds: int,
    firewall_policy_path: Path | None,
    firewall_policy_reload_seconds: int,
) -> dict:
    """Read the runtime policy and fail fast on bad reload settings or a malformed firewall policy."""
    policy: dict = {}
    if policy_path is not None:
        policy = read_json_file_for_cli(policy_path, label="policy file")
    if policy_reload_seconds < 0:
        raise click.ClickException("--policy-reload-seconds must be >= 0")
    if policy_reload_seconds > 0 and policy_path is None:
        raise click.ClickException("--policy-reload-seconds requires --policy")

    if firewall_policy_reload_seconds < 0:
        raise click.ClickException("--firewall-policy-reload-seconds must be >= 0")
    if firewall_policy_reload_seconds > 0 and firewall_policy_path is None:
        raise click.ClickException("--firewall-policy-reload-seconds requires --firewall-policy")
    # The same loader runs on every hot reload; failing here surfaces the
    # error before the gateway is up.
    if firewall_policy_path is not None:
        from agent_bom.firewall import FirewallPolicyError, load_firewall_policy_file

        try:
            load_firewall_policy_file(firewall_policy_path)
        except FirewallPolicyError as exc:
            raise click.ClickException(f"firewall policy invalid: {exc}") from exc
    return policy


def require_visual_leak_runtime(detect_visual_leaks: bool, allow_visual_leak_best_effort: bool) -> None:
    if not detect_visual_leaks or allow_visual_leak_best_effort:
        return
    try:
        from agent_bom.runtime.visual_leak_detector import require_visual_leak_runtime as _require_runtime

        _require_runtime()
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


def load_policy_bundle(policy_bundle_path: Path | None) -> list[dict]:
    if policy_bundle_path is None:
        return []
    raw_bundle = json.loads(policy_bundle_path.read_text(encoding="utf-8"))
    bundle_list = raw_bundle.get("policies", []) if isinstance(raw_bundle, dict) else raw_bundle
    if not isinstance(bundle_list, list):
        raise click.ClickException("--policy-bundle must be a JSON list of policies or {'policies': [...]}")
    policies = [p for p in bundle_list if isinstance(p, dict)]
    click.echo(f"loaded {len(policies)} control-plane policy/policies from {policy_bundle_path}")
    return policies


def load_oidc_discovery_shim() -> Any:
    from agent_bom.api.oidc_discovery_shim import OIDCDiscoveryShimConfig, OIDCDiscoveryShimError

    try:
        shim = OIDCDiscoveryShimConfig.from_env()
    except OIDCDiscoveryShimError as exc:
        raise click.ClickException(f"OIDC discovery shim config invalid: {exc}") from exc
    if shim is not None:
        click.echo(f"OIDC discovery shim enabled (issuer={shim.issuer})")
    return shim


def load_tool_scope_map(tool_scope_map: Path | None) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    if tool_scope_map is None:
        return mapping
    raw_map = read_json_file_for_cli(tool_scope_map, label="tool scope map")
    if not isinstance(raw_map, dict):
        raise click.ClickException("--tool-scope-map must be a JSON object of {tool_name: [scope, ...]}")
    for tool, scopes in raw_map.items():
        if isinstance(scopes, str):
            mapping[str(tool)] = [scopes]
        elif isinstance(scopes, list):
            mapping[str(tool)] = [str(s) for s in scopes if str(s).strip()]
        else:
            raise click.ClickException(f"--tool-scope-map value for {tool!r} must be a string or list of strings")
    click.echo(f"loaded OAuth scope requirements for {len(mapping)} tool(s)")
    return mapping


def _auth_summary(bearer_token: str | None, allow_insecure_no_auth: bool) -> str:
    if bearer_token:
        return "Bearer/API-key token required for incoming gateway clients"
    if allow_insecure_no_auth:
        return "Disabled by explicit override (--allow-insecure-no-auth)"
    return "Loopback-only without transport auth; add --bearer-token before exposing remotely"


def emit_startup_summary(**options: Any) -> None:
    from agent_bom.output.brand_tokens import emit_cli_runtime_summary

    emit_cli_runtime_summary("agent-bom gateway", startup_summary_rows(**options))


def startup_summary_rows(
    *,
    bind_url: str,
    registry: Any,
    policy: dict,
    bearer_token: str | None,
    allow_insecure_no_auth: bool,
    profile_enforcement: str,
    profile_environment: str,
    profile_issuer: str,
    detect_visual_leaks: bool,
    allow_visual_leak_best_effort: bool,
    policy_path: Path | None,
    policy_reload_seconds: int,
    firewall_policy_path: Path | None,
    firewall_policy_reload_seconds: int,
) -> list[tuple[str, str]]:
    from agent_bom.proxy_policy import summarize_policy_bundle

    policy_summary = summarize_policy_bundle(policy)
    profile_detail = f" ({profile_issuer.strip()} / {profile_environment.strip()})" if profile_enforcement != "off" else ""
    rows = [
        ("Bind", bind_url),
        ("Upstreams", f"{len(registry)} configured: {', '.join(registry.names()) or '(none)'}"),
        ("Auth", _auth_summary(bearer_token, allow_insecure_no_auth)),
        (
            "Policy",
            (
                f"{policy_summary['summary']} "
                f"Rules={policy_summary['total_rules']} "
                f"(block={policy_summary['blocking_rules']}, warn={policy_summary['advisory_rules']})"
            ),
        ),
        ("Client profiles", f"{profile_enforcement}" + profile_detail),
    ]
    if detect_visual_leaks:
        mode = "best-effort" if allow_visual_leak_best_effort else "required"
        rows.append(("Visual leaks", f"Enabled ({mode})"))
    if policy_path and policy_reload_seconds > 0:
        rows.append(("Policy reload", f"Policy hot reload: enabled every {policy_reload_seconds}s from {policy_path}"))
    rows.extend(_firewall_summary_rows(firewall_policy_path, firewall_policy_reload_seconds))
    return rows


def _firewall_summary_rows(firewall_policy_path: Path | None, firewall_policy_reload_seconds: int) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if firewall_policy_path is not None:
        from agent_bom.firewall import load_firewall_policy_file

        firewall_policy = load_firewall_policy_file(firewall_policy_path)
        rows.append(
            (
                "Firewall",
                f"{len(firewall_policy.rules)} rule(s) "
                f"(default={firewall_policy.default_decision.value}, mode={firewall_policy.enforcement_mode.value}) "
                f"from {firewall_policy_path}",
            )
        )
    if firewall_policy_path and firewall_policy_reload_seconds > 0:
        rows.append(
            (
                "Firewall reload",
                f"Firewall hot reload: enabled every {firewall_policy_reload_seconds}s from {firewall_policy_path}",
            )
        )
    return rows
