"""Loaders for top-level commands that are aliases or groups wired from several modules.

Each loader imports only the modules its command needs, so running one command
never pays for the rest of the CLI. Wiring is idempotent: groups and flags that
several commands share are set the same way whichever command loads first.
"""

from __future__ import annotations

import copy
import importlib
from typing import Any

import click


def _obj(module: str, attr: str) -> Any:
    return getattr(importlib.import_module(module), attr)


def _hidden_alias(command: click.Command, name: str) -> click.Command:
    alias = copy.copy(command)
    alias.hidden = True
    alias.name = name
    return alias


def load_agents_alias() -> click.Command:
    return _hidden_alias(_obj("agent_bom.cli.agents.scan_cmd", "scan"), "agents")


def load_validate_alias() -> click.Command:
    return _hidden_alias(_obj("agent_bom.cli._inventory", "validate"), "validate")


def load_guard() -> click.Command:
    """``guard`` moved to ``policy check``; the shared command stays hidden in both places."""
    guard: click.Command = _obj("agent_bom.cli._check", "guard_cmd")
    guard.hidden = True
    return guard


def load_api() -> click.Command:
    """REST-only server, folded into ``serve --no-ui`` and kept as a hidden alias."""
    api: click.Command = _obj("agent_bom.cli._server", "api_cmd")
    api.hidden = True
    return api


def load_registry() -> click.Command:
    """Available under ``mcp registry``; hidden at the top level and in ``mcp``."""
    registry: click.Command = _obj("agent_bom.cli._registry", "registry")
    registry.hidden = True
    return registry


def load_run() -> click.Command:
    run: click.Command = _obj("agent_bom.cli.run", "run_cmd")
    run.hidden = True
    return run


def load_mcp_server_alias() -> click.Command:
    return _hidden_alias(_obj("agent_bom.cli._server", "mcp_server_cmd"), "mcp-server")


def load_policy_templates_alias() -> click.Command:
    return _hidden_alias(_obj("agent_bom.cli._policy", "policy_template"), "policy-templates")


def load_policy() -> click.Group:
    policy_group: click.Group = _obj("agent_bom.cli._policy_group", "policy_group")
    template: click.Command = _obj("agent_bom.cli._policy", "policy_template")
    policy_group.add_command(template, "template")
    templates = copy.copy(template)
    setattr(templates, "deprecated", "Use `agent-bom policy template`.")
    templates.name = "templates"
    templates.hidden = True
    policy_group.add_command(templates, "templates")
    policy_group.add_command(_obj("agent_bom.cli._policy", "apply_command"), "apply")
    policy_group.add_command(load_guard(), "check")
    return policy_group


def load_runtime() -> click.Group:
    runtime_group: click.Group = _obj("agent_bom.cli._runtime_group", "runtime_group")
    runtime = importlib.import_module("agent_bom.cli._runtime")
    runtime_group.add_command(runtime.proxy_cmd, "proxy")
    runtime_group.add_command(runtime.audit_replay_cmd, "audit")
    runtime_group.add_command(runtime.audit_drain_dlq_cmd, "drain-dlq")
    runtime_group.add_command(runtime.proxy_bootstrap_cmd, "bootstrap")
    runtime_group.add_command(runtime.proxy_configure_cmd, "configure")
    runtime_group.add_command(runtime.protect_cmd, "protect")
    runtime_group.add_command(_hidden_alias(runtime.watch_cmd, "watch"), "watch")
    runtime_group.commands["configure"].hidden = True
    runtime_group.commands["protect"].hidden = True
    return runtime_group


def load_report() -> click.Group:
    report = importlib.import_module("agent_bom.cli._report_group")
    history = importlib.import_module("agent_bom.cli._history")
    group: click.Group = report.report_group
    group.add_command(history.history_cmd, "history")
    group.add_command(history.diff_cmd, "diff")
    group.add_command(history.rescan_command, "rescan")
    group.add_command(history.compliance_narrative_cmd, "compliance-narrative")
    group.add_command(report.pipeline_events_cmd, "pipeline-events")
    group.add_command(report.local_query_cmd, "query")
    group.add_command(report.local_storage_cmd, "storage")
    group.add_command(report.local_prune_cmd, "prune")
    group.add_command(_obj("agent_bom.cli._analysis", "analytics_cmd"), "analytics")
    return group


def load_mcp() -> click.Group:
    mcp = importlib.import_module("agent_bom.cli._mcp_group")
    inventory = importlib.import_module("agent_bom.cli._inventory")
    group: click.Group = mcp.mcp_group
    group.add_command(inventory.inventory, "inventory")
    group.add_command(mcp.mcp_scan_cmd, "scan")
    group.add_command(_obj("agent_bom.cli._analysis", "introspect_cmd"), "introspect")
    group.add_command(load_registry(), "registry")
    group.add_command(_obj("agent_bom.cli._server", "mcp_server_cmd"), "server")
    group.add_command(_hidden_alias(inventory.where, "where"), "where")
    group.add_command(inventory.validate, "validate")
    return group


def _frontdoor_command(name: str) -> click.Command:
    serve: click.Command = _obj("agent_bom.cli._server", "serve_cmd")
    scratch = click.Group()
    _obj("agent_bom.cli._frontdoor", "register_frontdoor")(scratch, serve)
    return scratch.commands[name]


def load_connect() -> click.Command:
    return _frontdoor_command("connect")


def load_up() -> click.Command:
    return _frontdoor_command("up")
