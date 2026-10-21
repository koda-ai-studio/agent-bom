"""Console remediation rendering helpers."""

from __future__ import annotations

from collections.abc import Sequence

from rich.rule import Rule

from agent_bom.core.severity import severity_rank
from agent_bom.finding import Asset, Finding, FindingSource, FindingType, blast_radius_to_finding
from agent_bom.models import AIBOMReport, Severity
from agent_bom.output.compact import _pct
from agent_bom.output.console_style import _console
from agent_bom.output.finding_views import (
    cve_findings,
    finding_references,
    finding_severity,
    package_ecosystem,
    package_name,
    package_version,
)
from agent_bom.remediation_commands import build_fix_command, build_remove_command, build_verify_command


def build_remediation_plan(blast_radii: Sequence[object]) -> list[dict]:
    """Group CVE findings into a prioritized remediation plan.

    Accepts legacy ``BlastRadius`` rows or unified ``Finding`` CVE rows. When
    passed BlastRadius objects, they are projected through ``blast_radius_to_finding``
    before grouping.

    Returns items sorted by grouped blast-radius risk: each item = one upgrade action that clears
    N vulns across M agents and frees exposed credentials.
    """
    from collections import defaultdict

    if not blast_radii:
        return []

    findings = [_blast_radius_like_to_finding(item) for item in blast_radii]

    groups: dict[tuple, dict] = defaultdict(_new_remediation_group)
    severity_order = {sev: severity_rank(sev.value) for sev in Severity}
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

    for finding in findings:
        key = (package_name(finding), package_ecosystem(finding), package_version(finding))
        _add_remediation_finding(groups[key], finding, severity_order)

    plan = []
    for g in groups.values():
        plan.append(_finish_remediation_group(g))

    plan.sort(
        key=lambda x: (
            priority_order.get(x["priority"], 99),
            -x["ranking_score"],
            -x["impact"],
            -x["credential_count"],
            -x["tool_count"],
            -x["agent_count"],
            x["package"],
        )
    )
    return plan


def print_remediation_plan(report: AIBOMReport) -> None:
    """Print a prioritized remediation plan with named assets and risk narrative."""
    try:
        all_cve: Sequence[object] = cve_findings(report)
    except TypeError:
        all_cve = list(getattr(report, "blast_radii", []) or [])
    if not all_cve:
        return

    plan = build_remediation_plan(all_cve)
    from agent_bom.security import sanitize_sensitive_payload

    sanitized_plan = sanitize_sensitive_payload(plan, max_str_len=10_000)
    plan = sanitized_plan if isinstance(sanitized_plan, list) else []
    # A malicious package sets fix=None to signal REMOVAL (not a version bump),
    # so it must be pulled out of the fix-based buckets. Without this it lands in
    # the "no fix yet — monitor upstream for patches" bucket, which tells the user
    # to keep a known-malicious dependency and wait — the opposite of the
    # required "remove immediately" action.
    malicious = [p for p in plan if p.get("is_malicious")]
    fixable = [p for p in plan if p["fix"] and not p.get("is_malicious")]
    unfixable = [p for p in plan if not p["fix"] and not p.get("is_malicious")]

    # Totals for percentage calculations
    total_agents = report.total_agents or 1
    all_creds: set[str] = set()
    all_tools: set[str] = set()
    for finding in all_cve:
        all_creds.update(getattr(finding, "exposed_credentials", []) or [])
        all_tools.update(getattr(finding, "exposed_tools", []) or [])
    total_creds = len(all_creds) or 1
    total_tools = len(all_tools) or 1

    _console().print()
    _console().print(Rule("Remediation Plan", style="green"))
    _console().print()

    _print_malicious(malicious)

    _print_fixable(fixable, total_agents, total_creds, total_tools)

    if unfixable:
        _console().print(f"  [dim yellow]⚠ {len(unfixable)} package(s) have no fix yet — monitor upstream for patches:[/dim yellow]")
        for item in unfixable[:10]:
            agents_str = f" ({', '.join(item['agents'][:3])})" if item["agents"] else ""
            _console().print(f"    [dim]• {item['package']}@{item['current']} — {', '.join(item['vulns'][:3])}{agents_str}[/dim]")
        _console().print()


def _is_mock_value(value: object) -> bool:
    return type(value).__module__ == "unittest.mock"


def _attr(obj: object, name: str, default: object = None) -> object:
    return getattr(obj, name, default)


def _text(value: object, default: str = "") -> str:
    if value is None or _is_mock_value(value):
        return default
    raw = getattr(value, "value", value)
    if raw is None or _is_mock_value(raw):
        return default
    return str(raw)


def _names(values: object) -> list[str]:
    if not values or _is_mock_value(values):
        return []
    names: list[str] = []
    iterable = values if isinstance(values, list | tuple | set) else []
    for item in iterable:
        name = _text(_attr(item, "name", item))
        if name:
            names.append(name)
    return names


def _list_text(values: object) -> list[str]:
    if not values or _is_mock_value(values):
        return []
    if not isinstance(values, list | tuple | set):
        return []
    return [_text(item) for item in values if _text(item)]


def _float(value: object, default: float = 0.0) -> float:
    if value is None or _is_mock_value(value):
        return default
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _blast_radius_like_to_finding(item: object) -> Finding:
    if isinstance(item, Finding):
        return item
    try:
        return blast_radius_to_finding(item)
    except TypeError:
        # Some legacy CLI tests and plugin adapters still pass BlastRadius-like
        # objects instead of the dataclass. Keep remediation tolerant while the
        # formatter migration converges on the unified Finding stream.
        vuln = _attr(item, "vulnerability")
        pkg = _attr(item, "package")
        package = _text(_attr(pkg, "name"), "unknown-package")
        version = _text(_attr(pkg, "version"))
        ecosystem = _text(_attr(pkg, "ecosystem"))
        vuln_id = _text(_attr(vuln, "id"), "UNKNOWN")
        severity = _text(_attr(vuln, "severity"), "unknown").lower()
        fixed_version = _text(_attr(vuln, "fixed_version")) or None
        references = _list_text(_attr(vuln, "references", []))
        identifier = f"pkg:{ecosystem}/{package}@{version}" if ecosystem and package and version else None
        return Finding(
            finding_type=FindingType.CVE,
            source=FindingSource.SBOM,
            asset=Asset(name=package, asset_type="package", identifier=identifier),
            severity=severity,
            title=f"{vuln_id} in {package}",
            cve_id=vuln_id,
            fixed_version=fixed_version,
            is_kev=bool(_attr(vuln, "is_kev", False)),
            evidence={
                "package_name": package,
                "package_version": version,
                "ecosystem": ecosystem,
                "references": references,
            },
            affected_agents=_names(_attr(item, "affected_agents", [])),
            affected_servers=_names(_attr(item, "affected_servers", [])),
            exposed_credentials=_list_text(_attr(item, "exposed_credentials", [])),
            exposed_tools=_list_text(_attr(item, "exposed_tools", [])),
            owasp_tags=_list_text(_attr(item, "owasp_tags", [])),
            atlas_tags=_list_text(_attr(item, "atlas_tags", [])),
            nist_ai_rmf_tags=_list_text(_attr(item, "nist_ai_rmf_tags", [])),
            owasp_mcp_tags=_list_text(_attr(item, "owasp_mcp_tags", [])),
            owasp_agentic_tags=_list_text(_attr(item, "owasp_agentic_tags", [])),
            eu_ai_act_tags=_list_text(_attr(item, "eu_ai_act_tags", [])),
            nist_csf_tags=_list_text(_attr(item, "nist_csf_tags", [])),
            iso_27001_tags=_list_text(_attr(item, "iso_27001_tags", [])),
            soc2_tags=_list_text(_attr(item, "soc2_tags", [])),
            cis_tags=_list_text(_attr(item, "cis_tags", [])),
            risk_score=_float(_attr(item, "risk_score", 0.0)),
            ai_risk_context=_text(_attr(item, "ai_risk_context")) or None,
        )


def _ranking_reasons(group: dict) -> list[str]:
    reasons: list[str] = []
    if group["has_kev"]:
        reasons.append("actively exploited")
    if group["creds"]:
        cred_count = len(group["creds"])
        reasons.append(f"{cred_count} exposed credential{'s' if cred_count != 1 else ''}")
    if group["tools"]:
        tool_count = len(group["tools"])
        reasons.append(f"{tool_count} reachable tool{'s' if tool_count != 1 else ''}")
    if group["agents"]:
        agent_count = len(group["agents"])
        reasons.append(f"{agent_count} affected agent{'s' if agent_count != 1 else ''}")
    if group["max_risk_score"]:
        reasons.append(f"blast radius risk {group['max_risk_score']:.1f}/10")
    return reasons


def _ranking_rationale(group: dict) -> str:
    reasons = group["ranking_reasons"]
    if not reasons:
        return f"Prioritized as {group['priority']} based on grouped remediation impact."
    if len(reasons) == 1:
        detail = reasons[0]
    else:
        detail = ", ".join(reasons[:-1]) + f", and {reasons[-1]}"
    return f"Prioritized as {group['priority']} because {detail}."


def _new_remediation_group() -> dict:
    return {
        "package": "",
        "ecosystem": "",
        "current": "",
        "fix": None,
        "reason": None,
        "command": None,
        "verify_command": None,
        "vulns": [],
        "agents": set(),
        "creds": set(),
        "tools": set(),
        "owasp": set(),
        "atlas": set(),
        "nist": set(),
        "owasp_mcp": set(),
        "owasp_agentic": set(),
        "eu_ai_act": set(),
        "nist_csf": set(),
        "iso_27001": set(),
        "soc2": set(),
        "cis": set(),
        "max_severity": Severity.NONE,
        "critical_count": 0,
        "high_count": 0,
        "has_kev": False,
        "ai_risk": False,
        "max_risk_score": 0.0,
        "references": set(),
        "suppressed_prerelease_fixes": set(),
        "is_malicious": False,
    }


def _add_remediation_finding(g: dict, finding: Finding, severity_order: dict[Severity, int]) -> None:
    pkg_name = package_name(finding)
    ecosystem = package_ecosystem(finding)
    current = package_version(finding)
    g["package"] = pkg_name
    g["ecosystem"] = ecosystem
    g["current"] = current
    _update_remediation_fix(g, finding, ecosystem, current)
    vuln_id = finding.cve_id or finding.id
    g["vulns"].append(vuln_id)
    g["agents"].update(finding.affected_agents)
    g["creds"].update(finding.exposed_credentials)
    g["tools"].update(finding.exposed_tools)
    g["owasp"].update(finding.owasp_tags)
    g["atlas"].update(finding.atlas_tags)
    g["nist"].update(finding.nist_ai_rmf_tags)
    g["owasp_mcp"].update(finding.owasp_mcp_tags)
    g["owasp_agentic"].update(finding.owasp_agentic_tags)
    g["eu_ai_act"].update(finding.eu_ai_act_tags)
    g["nist_csf"].update(finding.nist_csf_tags)
    g["iso_27001"].update(finding.iso_27001_tags)
    g["soc2"].update(finding.soc2_tags)
    g["cis"].update(finding.cis_tags)
    for ref in finding_references(finding):
        g["references"].add(ref)
    sev = finding_severity(finding)
    if severity_order.get(sev, 0) > severity_order.get(g["max_severity"], 0):
        g["max_severity"] = sev
    if sev == Severity.CRITICAL:
        g["critical_count"] += 1
    elif sev == Severity.HIGH:
        g["high_count"] += 1
    if finding.is_kev:
        g["has_kev"] = True
    if finding.ai_risk_context:
        g["ai_risk"] = True
    g["max_risk_score"] = max(g["max_risk_score"], finding.risk_score or 0.0)
    if getattr(finding, "is_malicious", False) or bool((finding.evidence or {}).get("package_is_malicious")):
        g["is_malicious"] = True


def _update_remediation_fix(g: dict, finding: Finding, ecosystem: str, current: str) -> None:
    # Only accept fixed_version values that are real forward upgrades for
    # the package ecosystem; this avoids downgrade/canary suggestions from
    # multi-branch or pre-release advisories.
    fv = finding.fixed_version
    if fv:
        from agent_bom.version_utils import compare_versions, is_prerelease_version

        if is_prerelease_version(fv, ecosystem):
            g["suppressed_prerelease_fixes"].add(fv)
        elif compare_versions(current, fv, ecosystem):
            if g["fix"] is None or compare_versions(g["fix"], fv, ecosystem):
                g["fix"] = fv


def _finish_remediation_group(g: dict) -> dict:
    g["vulns"] = sorted(set(g["vulns"]))
    g["agents"] = sorted(g["agents"])
    g["creds"] = sorted(g["creds"])
    g["tools"] = sorted(g["tools"])
    g["owasp"] = sorted(g["owasp"])
    g["atlas"] = sorted(g["atlas"])
    g["nist"] = sorted(g["nist"])
    g["owasp_mcp"] = sorted(g["owasp_mcp"])
    g["owasp_agentic"] = sorted(g["owasp_agentic"])
    g["eu_ai_act"] = sorted(g["eu_ai_act"])
    g["nist_csf"] = sorted(g["nist_csf"])
    g["iso_27001"] = sorted(g["iso_27001"])
    g["soc2"] = sorted(g["soc2"])
    g["cis"] = sorted(g["cis"])
    g["references"] = sorted(g["references"])
    g["suppressed_prerelease_fixes"] = sorted(g["suppressed_prerelease_fixes"])
    # Use the highest grouped blast-radius risk score so remediation stays
    # anchored to the canonical vulnerability risk model instead of a
    # separate package-level heuristic.
    g["impact"] = round(g["max_risk_score"], 1)
    if g["has_kev"] or g["critical_count"] >= 3:
        g["priority"] = "P1"
    elif g["critical_count"] > 0 or (g["high_count"] > 0 and g["creds"]):
        g["priority"] = "P2"
    elif g["high_count"] > 0:
        g["priority"] = "P3"
    else:
        g["priority"] = "P4"

    action = _remediation_action(g)
    g["credential_count"] = len(g["creds"])
    g["tool_count"] = len(g["tools"])
    g["agent_count"] = len(g["agents"])
    g["ranking_reasons"] = _ranking_reasons(g)
    g["ranking_rationale"] = _ranking_rationale(g)
    g["ranking_score"] = round(
        g["impact"]
        + (1.5 if g["has_kev"] else 0.0)
        + min(g["credential_count"] * 0.5, 2.0)
        + min(g["tool_count"] * 0.2, 1.0)
        + min(g["agent_count"] * 0.15, 0.75)
        + (0.25 if g["ai_risk"] else 0.0),
        2,
    )
    if g["creds"]:
        action += "; rotate exposed credentials"
    if g["tools"]:
        action += "; review reachable tool permissions"
    if g["has_kev"]:
        action += "; expedite patching due to active exploitation"
    g["action"] = action
    return g


def _remediation_action(g: dict) -> str:
    if g["is_malicious"]:
        action = f"Remove {g['package']} from all environments immediately"
        g["fix"] = None
        g["command"] = build_remove_command(g["ecosystem"], g["package"])
        g["verify_command"] = None
        g["reason"] = "known malicious package"
    elif g["fix"]:
        action = f"Upgrade {g['package']} to {g['fix']}"
        g["command"] = build_fix_command(g["ecosystem"], g["package"], g["fix"])
        g["verify_command"] = build_verify_command(g["ecosystem"], g["package"], g["fix"])
    else:
        action = f"Monitor {g['package']} upstream and isolate exposed surface"
        g["command"] = None
        g["verify_command"] = None
        if g["suppressed_prerelease_fixes"]:
            g["reason"] = "prerelease fix suppressed by default"
            action = f"Wait for a stable {g['package']} release; prerelease fix exists but is suppressed by default"
    return action


def _fixable_severity_styles() -> dict[Severity, str]:
    sev_style = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "#e67e22 bold",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
        Severity.NONE: "white",
    }
    return sev_style


def _print_malicious(malicious: list[dict]) -> None:
    if malicious:
        _console().print(
            f"  [red bold]☠ {len(malicious)} MALICIOUS package(s) — remove immediately (do not wait for a patch):[/red bold]\n"
        )
        for item in malicious:
            reason = item.get("reason") or "known malicious package"
            _console().print(
                f"    [white on red] MALICIOUS [/white on red] "
                f"[red bold]Remove {item['package']}@{item['current']}[/red bold] [dim]({reason})[/dim]"
            )
            if item.get("command"):
                _console().print(f"      [dim]$ {item['command']}[/dim]")
            if item["agents"]:
                _console().print(f"      [dim]agents:[/dim]  {', '.join(item['agents'][:3])}")
        _console().print()


def _print_fixable(fixable: list[dict], total_agents: int, total_creds: int, total_tools: int) -> None:
    sev_style = _fixable_severity_styles()
    if fixable:
        _console().print(f"  [bold]{len(fixable)} fixable upgrade(s) — ordered by grouped blast-radius risk:[/bold]\n")
        for i, item in enumerate(fixable, 1):
            sev = item["max_severity"]
            style = sev_style.get(sev, "white")
            kev_flag = " [red bold][KEV][/red bold]" if item["has_kev"] else ""
            ai_flag = " [magenta][AI-RISK][/magenta]" if item["ai_risk"] else ""

            # Header: upgrade package version → fix
            _console().print(
                f"  [{style}]{i}. upgrade {item['package']}[/{style}]  "
                f"[dim]{item['current']}[/dim] → [green bold]{item['fix']}[/green bold]"
                f"{kev_flag}{ai_flag}"
            )

            # Impact line with counts
            n_vulns = len(item["vulns"])
            n_agents = len(item["agents"])
            n_creds = len(item["creds"])
            n_tools = len(item["tools"])

            impact_parts = [f"clears {n_vulns} vuln(s)"]
            impact_parts.append(f"{n_agents} agent(s) protected ({_pct(n_agents, total_agents)})")
            if item["creds"]:
                impact_parts.append(f"frees {n_creds} credential(s) ({_pct(n_creds, total_creds)})")
            if item["tools"]:
                impact_parts.append(f"secures {n_tools} tool(s) ({_pct(n_tools, total_tools)})")
            _console().print(f"     [dim]{'  •  '.join(impact_parts)}[/dim]")

            # Named assets
            if item["agents"]:
                _console().print(f"     [dim]agents:[/dim]  {', '.join(item['agents'])}")
            if item["creds"]:
                _console().print(f"     [dim]credentials:[/dim]  [yellow]{', '.join(item['creds'])}[/yellow]")
            if item["tools"]:
                _console().print(
                    f"     [dim]tools:[/dim]  {', '.join(item['tools'][:8])}"
                    + (f" +{len(item['tools']) - 8} more" if len(item["tools"]) > 8 else "")
                )

            # Threat framework tags
            tags = []
            if item["owasp"]:
                tags.append("[purple]" + " ".join(item["owasp"]) + "[/purple]")
            if item["atlas"]:
                tags.append("[cyan]" + " ".join(item["atlas"]) + "[/cyan]")
            if item["nist"]:
                tags.append("[green]" + " ".join(item["nist"]) + "[/green]")
            if tags:
                _console().print(f"     [dim]mitigates:[/dim]  {' '.join(tags)}")

            # Risk narrative — what happens if NOT fixed. Suppress the
            # credential-reach clause entirely when the fix frees no
            # credentials, so it never reads "can reach no credentials".
            via = f" via {', '.join(item['agents'][:2])}" if item["agents"] else ""
            through = f" through {', '.join(item['tools'][:3])}" if item["tools"] else ""
            if item["creds"]:
                reach = f"can reach [yellow]{', '.join(item['creds'][:2])}[/yellow]{via}{through}"
            elif item["agents"] or item["tools"]:
                reach = f"widens the attack surface{via}{through}"
            else:
                reach = "widens the attack surface on this dependency"
            _console().print(f"     [dim red]⚠ if not fixed:[/dim red] [dim]attacker exploiting {item['vulns'][0]} {reach}[/dim]")
            _console().print()
