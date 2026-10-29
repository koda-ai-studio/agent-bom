"""Findings from every scanner the product ships, not just the posture one.

:mod:`agent_bom.demo_estate.enterprise_findings` raises CIS control failures over
the estate. Every one of its findings was a CIS check, so the estate's risk grew
with *control coverage* rather than with the estate — 439 findings across 2,068
assets, none of them a vulnerability, a leaked credential, an infrastructure-as-
code defect or a runtime policy violation. A security product whose demo shows
one scanner is demonstrating one scanner.

Four lanes are added here, and three decisions keep them honest.

**Real advisories, not invented ones.** Vulnerability findings are built from
:mod:`agent_bom.demo_advisories` — the curated catalog of genuine published
CVE/GHSA ids with their real CWE, CVSS and KEV status that the bundled demo
already uses. Inventing a CVE number, or pairing a real one with a version it
does not affect, produces a demo that a reviewer can disprove in one lookup.

**Production converters, then one explicit re-binding.** Each lane goes through
the same function a live scan uses — :func:`blast_radius_to_finding`,
:func:`secret_dict_to_finding`, :func:`iac_finding_to_finding` — so severity,
compliance classification and remediation are whatever production does. Those
converters key the asset on a *code-layer* identity (a purl, a ``file:line``),
which is correct for a repository scan and wrong for an estate: #4637 requires
one id scheme, and a finding whose asset id is a file path cannot join the
inventory. :func:`bind_to_inventory` re-points it at the estate asset the file
provisions or the image contains, keeping the code-layer location as evidence.
It is one function, applied identically by every lane, so there is no second
spelling to reconcile.

**A finding never invents its target.** Every lane iterates the inventory, so
the asset exists before the finding does. There is no path here that
materialises a stub.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from typing import Any

from agent_bom.demo_advisories import DEMO_ADVISORIES, DEMO_EPSS_SOURCE, DemoAdvisory
from agent_bom.demo_estate.enterprise import EnterpriseEstate, EstateAsset
from agent_bom.demo_estate.enterprise_ai import AI_LANE_TAG
from agent_bom.demo_estate.enterprise_risk_rules import _AI_RULES as _AI_RULES
from agent_bom.demo_estate.enterprise_risk_rules import _DATA_RULES as _DATA_RULES
from agent_bom.demo_estate.enterprise_risk_rules import _IAC_RULES as _IAC_RULES
from agent_bom.demo_estate.enterprise_risk_rules import _IDENTITY_RULES as _IDENTITY_RULES
from agent_bom.demo_estate.enterprise_risk_rules import _TOOL_RULES as _TOOL_RULES
from agent_bom.demo_estate.enterprise_risk_rules import _DataRule as _DataRule
from agent_bom.demo_estate.enterprise_risk_rules import _IacRule as _IacRule
from agent_bom.demo_estate.enterprise_risk_rules import _RuntimeRule as _RuntimeRule
from agent_bom.finding import (
    Asset,
    Finding,
    FindingSource,
    FindingType,
    blast_radius_to_finding,
    iac_finding_to_finding,
    secret_dict_to_finding,
    stable_id,
)

ESTATE_RISK_VERSION = "enterprise_risk.v1"


def _seed(*parts: str) -> int:
    return int.from_bytes(hashlib.sha256("|".join(parts).encode("utf-8")).digest()[:4], "big")


def vulnerable_version_for(advisory: DemoAdvisory) -> str:
    """Return the explicit published release selected for this advisory.

    Do not manufacture release numbers by decrementing a patch version:
    projects can skip version numbers, especially calendar-versioned packages.
    """
    if not advisory.sample_version:
        raise ValueError(f"No published sample version configured for {advisory.vuln_id}")
    return advisory.sample_version


def advisory_catalog() -> tuple[tuple[str, str, str, DemoAdvisory], ...]:
    """``(ecosystem, package, affected_version, advisory)`` for every curated row."""
    return tuple(
        (advisory.ecosystem, advisory.package, vulnerable_version_for(advisory), advisory)
        for advisory in DEMO_ADVISORIES
        if advisory.estate_sample
    )


# One ``Asset.asset_type`` per estate asset, for every lane.
#
# ``Asset.canonical_id`` includes asset_type, identifier and provider scope, so lanes
# that describe the SAME inventoried row with different asset_types mint two
# canonical ids for one asset — and the findings list, the graph and the exports
# stop joining. The posture lane goes through ``cloud_cis_check_to_finding``,
# which always writes ``cloud_resource``; anything the posture lane can also
# reach must therefore say ``cloud_resource`` too. This map holds only the rows
# posture never touches.
_ASSET_TYPE_OVERRIDES: dict[str, str] = {
    "package": "package",
    "container_image": "container",
    "repository": "repository",
    "workflow": "ci_job",
    "server": "mcp_server",
    "tool": "mcp_tool",
    "agent": "agent",
    "deployment": "workload",
    "hosted_model": "model",
    "model_artifact": "model",
}

_CLOUD_ASSET_TYPE = "cloud_resource"


def estate_asset_type(asset: EstateAsset) -> str:
    """The one ``Asset.asset_type`` every lane must use for this estate row."""
    return _ASSET_TYPE_OVERRIDES.get(asset.resource_type, _CLOUD_ASSET_TYPE)


def _classify(finding: Finding) -> Finding:
    """Run the product's own framework selection over a finding.

    Some converters call this internally and some do not. Applying it here for
    the ones that do not is what keeps every lane visible in the compliance hub
    posture instead of only the lanes whose converter happened to be written
    after the hub existed.
    """
    from agent_bom.compliance_hub import apply_hub_classification

    return apply_hub_classification(finding)


def bind_to_inventory(finding: Finding, asset: EstateAsset, estate: EnterpriseEstate, *, location: str = "") -> Finding:
    """Re-point a converter's finding at the inventoried asset it concerns.

    The production converters name the artifact they read — a purl, a
    ``file:line`` — which is the right identity for a repository scan and the
    wrong one for an estate, where every finding must resolve to a row the
    inventory already holds (#4637). The artifact identity is not discarded: it
    stays in ``evidence`` and in ``asset.location``, so the chain still shows
    *which file* and *which package*, it just hangs off the asset that owns them.

    One function, used by every lane, so there is exactly one spelling of the
    estate's finding-to-asset edge.
    """
    from agent_bom.finding_scope import normalize_account_ref

    account_ref = normalize_account_ref(asset.provider, asset.account_scope)
    finding.asset = Asset(
        name=asset.display_name,
        asset_type=estate_asset_type(asset),
        identifier=asset.asset_id,
        location=location or finding.asset.location or asset.native_id,
        provider=asset.provider,
        account_ref=account_ref,
        region=asset.region or None,
        environment=asset.environment or None,
    )
    finding.provider = asset.provider
    finding.account_ref = account_ref
    finding.region = asset.region or None
    finding.environment = asset.environment or None
    finding.evidence.update(
        {
            "resource_id": asset.asset_id,
            "resource_name": asset.display_name,
            "resource_type": asset.resource_type,
            "tenant_id": estate.tenant_id,
            "synthetic": True,
            "fictional": True,
            "disclosure": estate.disclosure,
            "estate_id": estate.estate_id,
            "data_classifications": list(asset.data_classifications),
        }
    )
    return finding


# ── Vulnerabilities ──────────────────────────────────────────────────────────


def build_vulnerability_evidence(estate: EnterpriseEstate) -> tuple[tuple[Any, Finding], ...]:
    """One CVE per inventoried package that a curated advisory actually covers.

    The package rows were generated *from* the advisory catalog, so the join is
    total by construction: a package with no matching advisory would mean the
    inventory and the catalog had drifted, and it is skipped rather than given an
    invented vulnerability.
    """
    from agent_bom.demo_estate.estate_cve_inputs import estate_blast_radius

    by_key = {(row[0], row[1], row[2]): row[3] for row in advisory_catalog()}
    images = {asset.asset_id: asset for asset in estate.assets if asset.resource_type == "container_image"}

    pairs: list[tuple[object, Finding]] = []
    for asset in estate.assets:
        if asset.resource_type != "package":
            continue
        ecosystem = asset.tags.get("ecosystem", "")
        name = asset.tags.get("package_name", "")
        version = asset.tags.get("package_version", "")
        advisory = by_key.get((ecosystem.lower(), name, version))
        if advisory is None:
            continue

        image = images.get(asset.tags.get("container_image", ""))
        blast_radius = estate_blast_radius(asset, advisory)
        finding = blast_radius_to_finding(blast_radius)
        bind_to_inventory(finding, asset, estate, location=asset.native_id)
        # The converter keys a finding on (advisory, package) because a
        # repository scan sees each package once. An estate ships the same
        # package inside twenty-one images, so that key collapsed twenty-one
        # distinct exposures onto one id — the same "dedupe key omits the scope"
        # defect that has cost this repo a cross-tenant row before. The scope
        # here is the inventoried package row.
        finding.id = stable_id("estate-vuln", advisory.vuln_id, asset.asset_id)
        finding.evidence.update(
            {
                # Every lane states what was observed and what was expected.
                # For a vulnerability that is the version edge — not a
                # fabricated "configuration", the actual finding: this version
                # is installed, the advisory fixes it in that one.
                "configuration": {
                    "setting": f"{ecosystem} package version",
                    "observed": f"{name}@{version}",
                    "expected": f"{name}>={advisory.fixed}",
                },
                "package_purl": asset.native_id,
                "package_ecosystem": ecosystem,
                "advisory_source": advisory.source,
                # Pinned published FIRST EPSS; name the snapshot it came from.
                "epss_source": DEMO_EPSS_SOURCE,
                "container_image": image.asset_id if image is not None else "",
                "container_image_name": image.display_name if image is not None else "",
                "image_signed": image.tags.get("signed", "") if image is not None else "",
            }
        )
        pairs.append((blast_radius, finding))
    return tuple(pairs)


def build_vulnerability_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """The estate's CVE findings, without their blast radii."""
    return tuple(finding for _blast_radius, finding in build_vulnerability_evidence(estate))


def build_vulnerability_blast_radii(estate: EnterpriseEstate) -> tuple[Any, ...]:
    """The blast radii behind those findings, for the report's legacy CVE array.

    Both halves have to reach the scan report, and this is the reason.
    ``output.finding_views.cve_findings`` reads ``report.blast_radii`` in
    preference to the unified findings list, and the unified JSON ``findings``
    array excludes ``CVE`` by design — CVEs travel in the vulnerability array.
    So an estate that contributed CVE *findings* and no blast radii had all 768
    of them silently dropped between the seeder and ``/v1/findings``: the demo
    reported 1,833 of 2,601 seeded rows, with the entire vulnerability lane
    missing and nothing anywhere saying so.
    """
    return tuple(blast_radius for blast_radius, _finding in build_vulnerability_evidence(estate))


# ── Hardcoded secrets ────────────────────────────────────────────────────────

_SECRET_KINDS: tuple[tuple[str, str, str, str], ...] = (
    ("aws_access_key_id", "cloud_credential", "critical", ".github/workflows/deploy.yml"),
    ("snowflake_password", "database_credential", "high", "src/warehouse/client.py"),
    ("openai_api_key", "model_provider_key", "high", "services/copilot/config.py"),
    ("github_pat", "vcs_token", "high", "scripts/release.sh"),
    ("private_key_pem", "signing_key", "critical", "deploy/certs/service.pem"),
    ("slack_webhook", "webhook_url", "medium", "ops/alerting/notify.py"),
)


def build_secret_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Committed credentials, bound to the repository that holds them.

    The scanner's own identity for a secret is ``file:line`` — correct for the
    repository scan, unusable as an estate join. The repository is the
    inventoried thing; the path stays in evidence, which is what a remediator
    actually needs.
    """
    findings: list[Finding] = []
    for asset in estate.assets:
        if asset.resource_type != "repository":
            continue
        seed = _seed("secret", asset.asset_id)
        # Roughly a third of repositories carry one. An estate where every
        # repository leaks is a lint rule, not a posture.
        if seed % 3 != 0:
            continue
        for offset in range(1 + (seed // 5) % 2):
            kind, category, severity, path = _SECRET_KINDS[(seed + offset) % len(_SECRET_KINDS)]
            line = 12 + ((seed >> (offset * 3)) % 180)
            finding = secret_dict_to_finding(
                {
                    "file": f"{asset.display_name}/{path}",
                    "line": line,
                    "type": kind,
                    "category": category,
                    "severity": severity,
                    # Never a value, not even a synthetic one: the converter
                    # redacts, and handing it something that looks like a secret
                    # teaches the demo to carry secret-shaped strings.
                    "preview": "***REDACTED***",
                }
            )
            bind_to_inventory(finding, asset, estate, location=f"{asset.display_name}/{path}")
            # ``secret_dict_to_finding`` sets no framework classification — it
            # predates the hub — so a secret would evidence no control and drop
            # out of the compliance posture entirely. Every other lane's
            # converter already does this internally.
            # The controls a committed credential genuinely evidences, from the
            # catalogs this repo ships. ``secret_dict_to_finding`` sets none.
            finding.owasp_tags = ["LLM02"]
            finding.owasp_mcp_tags = ["MCP01"]
            finding.nist_800_53_tags = ["IA-5"]
            _classify(finding)
            finding.evidence.update(
                {
                    "configuration": {
                        "setting": f"{kind} storage",
                        "observed": f"hardcoded at {path}:{line}",
                        "expected": "loaded from an environment variable or secret manager",
                    },
                    "repository": asset.asset_id,
                    "commit_sha": hashlib.sha256(f"{asset.asset_id}:{offset}".encode()).hexdigest()[:40],
                    "branch": "main",
                }
            )
            findings.append(finding)
    return tuple(findings)


_IAC_BY_TYPE: dict[str, tuple[_IacRule, ...]] = {}
for _rule in _IAC_RULES:
    for _resource_type in _rule.resource_types:
        _IAC_BY_TYPE[_resource_type] = (*_IAC_BY_TYPE.get(_resource_type, ()), _rule)


def build_iac_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Misconfigurations in the code that declares the resource.

    Bound to the resource, not to the ``.tf`` file. The file path is the
    remediation target and stays in evidence; the *asset* is what the graph, the
    exposure path and the account roll-up need to join on.
    """
    findings: list[Finding] = []
    for asset in estate.assets:
        rules = _IAC_BY_TYPE.get(asset.resource_type)
        if not rules:
            continue
        for rule in rules:
            seed = _seed("iac", asset.asset_id, rule.rule_id)
            # An IaC defect is a property of a module, so it repeats across the
            # resources that module produces — but not across all of them.
            if seed % 100 >= 24:
                continue
            module = f"infra/{asset.provider}/{asset.resource_type}s/main.tf"
            if rule.category == "kubernetes":
                module = f"deploy/k8s/{asset.display_name}.yaml"
            elif rule.category == "dockerfile":
                module = f"services/{asset.display_name.split(':')[0]}/Dockerfile"
            # Claim only the frameworks this rule actually evidences. Every IaC
            # rule used to declare ``["CIS", "NIST-800-53"]`` regardless — so
            # "resource declared without an ownership tag" asserted CIS
            # coverage it cannot support, and a consumer reading the compliance
            # posture was told a control had been evaluated when nothing had
            # evaluated it. Half these rules have no CIS twin at all, and
            # saying so is the accurate answer.
            cis_check = rule.cis_checks.get(asset.provider)
            frameworks = (["CIS"] if cis_check else []) + (["NIST-800-53"] if rule.nist_800_53 else [])
            finding = iac_finding_to_finding(
                {
                    "rule_id": rule.rule_id,
                    "file_path": module,
                    "line_number": 8 + (seed % 220),
                    "category": rule.category,
                    "severity": rule.severity,
                    "title": rule.title,
                    "message": f"{rule.message} Declared resource: {asset.display_name}.",
                    "remediation": rule.remediation,
                    "compliance": frameworks,
                }
            )
            bind_to_inventory(finding, asset, estate, location=module)
            finding.evidence["configuration"] = {
                "setting": rule.setting,
                "observed": rule.observed,
                "expected": rule.expected,
            }
            # ``check_id`` is the join key every posture consumer reads. The
            # rule id already IS the check identity, so emitting it only as
            # ``rule_id`` left this lane unjoinable to everything the cspm
            # domain is expected to support.
            finding.evidence["check_id"] = rule.rule_id
            if cis_check:
                finding.evidence["control_id"] = f"CIS-{cis_check}"
            if rule.nist_800_53:
                finding.nist_800_53_tags = list(rule.nist_800_53)
            # ``iac_finding_to_finding`` derives its id from the file path, and
            # one module declares many resources — so without re-deriving it,
            # every resource from one module collapsed onto a single finding id.
            finding.id = stable_id("estate-iac", rule.rule_id, asset.asset_id)
            _classify(finding)
            findings.append(finding)
    return tuple(findings)


def _runtime_finding(rule: _RuntimeRule, asset: EstateAsset, estate: EnterpriseEstate, *, evidence: dict[str, object]) -> Finding:
    from agent_bom.compliance_hub import apply_hub_classification
    from agent_bom.finding_scope import normalize_account_ref

    account_ref = normalize_account_ref(asset.provider, asset.account_scope)
    finding = Finding(
        finding_type=rule.finding_type,
        source=rule.source,
        asset=Asset(
            name=asset.display_name,
            asset_type=estate_asset_type(asset),
            identifier=asset.asset_id,
            location=asset.native_id,
            provider=asset.provider,
            account_ref=account_ref,
            region=asset.region or None,
            environment=asset.environment or None,
        ),
        severity=rule.severity,
        provider=asset.provider,
        account_ref=account_ref,
        region=asset.region or None,
        environment=asset.environment or None,
        title=f"{rule.title}: {asset.display_name}",
        description=rule.description,
        remediation_guidance=rule.remediation,
        evidence={
            **evidence,
            "check_id": rule.rule_id,
            "configuration": {
                "setting": rule.setting,
                "observed": rule.observed,
                "expected": rule.expected,
            },
        },
        owasp_tags=list(rule.owasp),
        owasp_mcp_tags=list(rule.owasp_mcp),
        owasp_agentic_tags=list(rule.owasp_agentic),
        nist_800_53_tags=list(rule.nist_800_53),
        id=stable_id("estate-runtime", rule.finding_type.value, asset.asset_id),
    )
    bind_to_inventory(finding, asset, estate)
    # Declare the frameworks whose controls this rule actually names. The hub's
    # selection table has no row for every (source, finding_type) pair the
    # product emits — ``CLOUD_SECURITY`` + ``CIEM_OVER_PRIVILEGE`` resolves to
    # nothing — and a finding classified into no framework is invisible to the
    # compliance posture no matter how many control tags it carries. This adds
    # no crosswalk: it names exactly the frameworks whose codes are on the rule.
    declared = [
        slug
        for slug, tags in (
            ("owasp-llm", rule.owasp),
            ("owasp-mcp", rule.owasp_mcp),
            ("owasp-agentic", rule.owasp_agentic),
            ("nist-800-53", rule.nist_800_53),
        )
        if tags
    ]
    finding.applicable_frameworks = declared
    return apply_hub_classification(finding)


def build_runtime_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Runtime and policy violations on the AI surface and its identities.

    These are the findings that only exist because the estate is *running*: a
    tool whose arguments reach a statement, an identity whose grants exceed what
    the audit log shows it using, a model served with no attestation. They are
    the lane a posture scanner cannot produce, and without them the demo's AI
    surface carries configuration risk and nothing else.
    """
    findings: list[Finding] = []
    for asset in estate.assets:
        if asset.resource_type == "tool":
            for rule in _TOOL_RULES:
                seed = _seed("runtime", asset.asset_id, rule.finding_type.value)
                writes = asset.tags.get("write_capable") == "true"
                if rule.finding_type is FindingType.EXFILTRATION and not writes:
                    continue
                if seed % 100 >= (32 if writes else 20):
                    continue
                findings.append(
                    _runtime_finding(
                        rule,
                        asset,
                        estate,
                        evidence={
                            "mcp_server": asset.tags.get("mcp_server", ""),
                            "write_capable": writes,
                            "gateway_policy": "mcp-prod-readonly-v3",
                            "observed_calls": 40 + (seed % 900),
                        },
                    )
                )
        elif asset.resource_type in {"iam_role", "service_principal", "service_account", "role"}:
            if asset.tags.get("over_permissive") != "true":
                continue
            for rule in _IDENTITY_RULES:
                seed = _seed("runtime", asset.asset_id, rule.finding_type.value)
                findings.append(
                    _runtime_finding(
                        rule,
                        asset,
                        estate,
                        evidence={
                            "granted_actions": 60 + (seed % 120),
                            "used_actions": seed % 12,
                            "evaluation_window_days": 90,
                        },
                    )
                )
        elif asset.tags.get(AI_LANE_TAG):
            for rule in _AI_RULES:
                seed = _seed("runtime", asset.asset_id, rule.finding_type.value)
                if rule.finding_type is FindingType.PROMPT_SECURITY and asset.resource_type not in {
                    "prompt_template",
                    "bedrock_agent",
                    "vertex_agent",
                    "agent",
                }:
                    continue
                if rule.finding_type is FindingType.MODEL_INTEGRITY and asset.resource_type not in {
                    "hosted_model",
                    "model_artifact",
                    "foundation_model",
                    "vertex_model",
                    "sagemaker_model",
                }:
                    continue
                if seed % 100 >= 38:
                    continue
                findings.append(
                    _runtime_finding(
                        rule,
                        asset,
                        estate,
                        evidence={
                            "ai_lane": asset.tags.get(AI_LANE_TAG, ""),
                            "model_family": asset.tags.get("model_family", ""),
                            "guardrail_attached": asset.tags.get("guardrail", "none"),
                        },
                    )
                )
    return tuple(findings)


def build_data_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Data-security-posture findings on the estate's inventoried data assets.

    Without this lane the demo populated four of the product's five posture
    lanes and rendered DSPM as zero — on a healthcare estate whose headline
    incident chain ends at a PHI table. An empty lane reads as "we do not do
    this", which is the opposite of true, and it is the lane a
    vulnerability-only scanner cannot produce at all.

    Routed to DSPM by ``FindingType.SENSITIVE_DATA``, which
    ``security_domain_for`` treats as decisive regardless of which provider
    surfaced it — so this needs no new taxonomy, only findings.
    """
    from agent_bom.compliance_hub import apply_hub_classification

    findings: list[Finding] = []
    for asset in estate.assets:
        if asset.provider != "snowflake":
            continue
        for rule in _DATA_RULES:
            if asset.resource_type not in rule.resource_types:
                continue
            seed = _seed("data", asset.asset_id, rule.rule_id)
            if seed % 100 >= rule.rate:
                continue
            account_ref = f"snowflake:{asset.account_scope}"
            finding = Finding(
                finding_type=rule.finding_type,
                source=FindingSource.DSPM,
                asset=Asset(
                    name=asset.display_name,
                    asset_type=estate_asset_type(asset),
                    identifier=asset.asset_id,
                    location=asset.native_id,
                    provider="snowflake",
                    account_ref=account_ref,
                ),
                severity=rule.severity,
                provider="snowflake",
                account_ref=account_ref,
                region=asset.region or None,
                environment=asset.environment or None,
                title=f"{rule.title}: {asset.display_name}",
                description=rule.description,
                remediation_guidance=rule.remediation,
                evidence={
                    # ``check_id`` is the join key every posture consumer reads;
                    # the rule id IS the check identity.
                    "check_id": rule.rule_id,
                    "data_classification": rule.classification,
                    "category": "sensitive-data-access",
                    "configuration": {
                        "setting": rule.setting,
                        "observed": rule.observed,
                        "expected": rule.expected,
                    },
                },
                nist_800_53_tags=list(rule.nist_800_53),
                id=stable_id("estate-data", rule.rule_id, asset.asset_id),
            )
            bind_to_inventory(finding, asset, estate)
            # Declare the frameworks whose controls this rule actually names.
            # The hub's selection table has no row for (DSPM, SENSITIVE_DATA),
            # and a finding classified into no framework is invisible to the
            # compliance posture no matter how many control tags it carries —
            # the same gap the runtime lane hit. This adds no crosswalk: it
            # names exactly the frameworks whose codes are on the rule.
            finding.applicable_frameworks = ["nist-800-53"] if rule.nist_800_53 else []
            findings.append(apply_hub_classification(finding))
    return tuple(findings)


def build_risk_findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    """Every non-posture lane, in one deterministic order."""
    lanes: Iterable[Sequence[Finding]] = (
        build_vulnerability_findings(estate),
        build_secret_findings(estate),
        build_iac_findings(estate),
        build_runtime_findings(estate),
        build_data_findings(estate),
    )
    return tuple(finding for lane in lanes for finding in lane)


__all__ = [
    "ESTATE_RISK_VERSION",
    "advisory_catalog",
    "build_vulnerability_blast_radii",
    "build_vulnerability_evidence",
    "bind_to_inventory",
    "build_data_findings",
    "build_iac_findings",
    "build_risk_findings",
    "build_runtime_findings",
    "build_secret_findings",
    "build_vulnerability_findings",
    "vulnerable_version_for",
]
