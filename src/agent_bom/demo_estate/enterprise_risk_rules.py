"""Deterministic sample risk rules used to build the enterprise estate."""

from __future__ import annotations

from agent_bom.finding import FindingSource, FindingType


# ── Infrastructure as code ───────────────────────────────────────────────────
class _IacRule:
    """One infrastructure-as-code rule, with the declaration it checks.

    ``setting``/``observed``/``expected`` are the block in the module and what it
    should have said. Every lane in this file carries that pair, because a
    finding that cannot say what it saw and what it wanted is not actionable —
    and because the demo's rendered chain asserts the edge on every row.
    """

    __slots__ = (
        "rule_id",
        "title",
        "message",
        "remediation",
        "severity",
        "category",
        "resource_types",
        "setting",
        "observed",
        "expected",
        "cis_checks",
        "nist_800_53",
    )

    def __init__(
        self,
        rule_id: str,
        title: str,
        message: str,
        remediation: str,
        severity: str,
        category: str,
        resource_types: tuple[str, ...],
        *,
        setting: str,
        observed: str,
        expected: str,
        cis_checks: dict[str, str] | None = None,
        nist_800_53: tuple[str, ...] = (),
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.message = message
        self.remediation = remediation
        self.severity = severity
        self.category = category
        self.resource_types = resource_types
        self.setting = setting
        self.observed = observed
        self.expected = expected
        # Keyed by provider: the same declaration is checked differently per
        # cloud, and only some rules have a runtime CIS twin at all. A rule with
        # no entry for the asset's provider claims no CIS coverage rather than
        # borrowing another cloud's control id.
        self.cis_checks = dict(cis_checks or {})
        self.nist_800_53 = nist_800_53


_IAC_RULES: tuple[_IacRule, ...] = (
    _IacRule(
        "TF-S3-001",
        "Bucket declared without server-side encryption",
        "The bucket resource omits a server_side_encryption_configuration block.",
        "Add a server_side_encryption_configuration block with a KMS key reference.",
        "high",
        "terraform",
        ("bucket", "storage_account"),
        setting="server_side_encryption_configuration",
        observed="block absent",
        expected="block present with a kms_master_key_id",
        cis_checks={"aws": "2.1.2"},
        nist_800_53=("SC-28",),
    ),
    _IacRule(
        "TF-IAM-002",
        "Policy document grants Action '*' on Resource '*'",
        "The policy document attached to this role grants unrestricted actions.",
        "Replace the wildcard statement with the actions the workload actually calls.",
        "critical",
        "terraform",
        ("iam_role", "service_principal", "service_account", "role"),
        setting="policy_document.statement.action",
        observed='Action "*" on Resource "*"',
        expected="the actions the workload calls, on named resources",
        cis_checks={"aws": "1.16"},
        nist_800_53=("AC-6",),
    ),
    _IacRule(
        "TF-NET-003",
        "Security group opens an admin port to 0.0.0.0/0",
        "An ingress rule allows tcp/22 from any address.",
        "Restrict the ingress CIDR to the approved bastion range.",
        "high",
        "terraform",
        ("instance", "virtual_machine", "cluster"),
        setting="ingress.cidr_blocks",
        observed="0.0.0.0/0 on tcp/22",
        expected="the approved bastion CIDR",
        cis_checks={"aws": "5.2", "gcp": "3.6"},
        nist_800_53=("SC-7",),
    ),
    _IacRule(
        "K8S-POD-004",
        "Container runs without a read-only root filesystem",
        "securityContext.readOnlyRootFilesystem is unset on the pod template.",
        "Set securityContext.readOnlyRootFilesystem: true and mount writable paths explicitly.",
        "medium",
        "kubernetes",
        ("deployment",),
        setting="securityContext.readOnlyRootFilesystem",
        observed="unset",
        expected="true",
        nist_800_53=("CM-7",),
    ),
    _IacRule(
        "K8S-RBAC-005",
        "ClusterRoleBinding grants cluster-admin to a workload identity",
        "The binding gives a service account full cluster administration.",
        "Bind the workload to a namespaced Role with the verbs it uses.",
        "critical",
        "kubernetes",
        ("cluster",),
        setting="roleRef.name",
        observed="cluster-admin",
        expected="a namespaced Role scoped to the verbs used",
        nist_800_53=("AC-6",),
    ),
    _IacRule(
        "TF-AI-006",
        "Model endpoint declared with public network access",
        "The endpoint sets public network access enabled and no private endpoint.",
        "Disable public network access and front the endpoint with a private endpoint.",
        "high",
        "terraform",
        ("sagemaker_endpoint", "vertex_endpoint", "azure_openai_deployment", "spcs_service", "gemini_api"),
        setting="public_network_access",
        observed="Enabled with no private endpoint",
        expected="Disabled, fronted by a private endpoint",
        nist_800_53=("SC-7",),
    ),
    _IacRule(
        "TF-TAG-008",
        "Resource declared without an ownership tag",
        "The module omits the owner tag the tagging policy requires.",
        "Add the owner tag to the module's default_tags so every resource it creates inherits it.",
        "low",
        "terraform",
        ("bucket", "instance", "database", "virtual_machine", "table", "function", "warehouse", "share"),
        setting="default_tags.owner",
        observed="absent",
        expected="the owning team's address",
        nist_800_53=("CM-8",),
    ),
    _IacRule(
        "DKR-IMG-007",
        "Image build does not pin a digest for its base image",
        "The Dockerfile FROM line references a mutable tag.",
        "Pin the base image by digest and rebuild on advisory, not on tag movement.",
        "medium",
        "dockerfile",
        ("container_image",),
        setting="FROM",
        observed="a mutable tag",
        expected="a pinned image digest",
        nist_800_53=("CM-2",),
    ),
)


# ── Runtime and policy ───────────────────────────────────────────────────────
class _RuntimeRule:
    """A runtime detection, with the controls it genuinely evidences.

    ``controls`` is spelled per framework because a finding with no control tag
    is invisible to the compliance posture — it lands in the findings list and
    nowhere else. Every code below is drawn from the catalogs this repo already
    ships (``owasp.OWASP_LLM_TOP10``, ``owasp_mcp.OWASP_MCP_TOP10``,
    ``owasp_agentic.OWASP_AGENTIC_TOP10``, ``nist_800_53.NIST_800_53``), never
    invented, and ``tests/test_estate_v2_scale.py`` asserts they still exist.
    """

    __slots__ = (
        "rule_id",
        "finding_type",
        "source",
        "title",
        "description",
        "remediation",
        "severity",
        "setting",
        "observed",
        "expected",
        "owasp",
        "owasp_mcp",
        "owasp_agentic",
        "nist_800_53",
    )

    def __init__(
        self,
        rule_id: str,
        finding_type: FindingType,
        source: FindingSource,
        title: str,
        description: str,
        remediation: str,
        severity: str,
        *,
        setting: str,
        observed: str,
        expected: str,
        owasp: tuple[str, ...] = (),
        owasp_mcp: tuple[str, ...] = (),
        owasp_agentic: tuple[str, ...] = (),
        nist_800_53: tuple[str, ...] = (),
    ) -> None:
        # The rule *is* the check identity. Without it the runtime lane reached
        # the findings list with nothing to join on, so every consumer keyed on
        # ``check_id`` — posture rollups, the graph projection, the compliance
        # hub — simply skipped it.
        self.rule_id = rule_id
        self.finding_type = finding_type
        self.source = source
        self.title = title
        self.description = description
        self.remediation = remediation
        self.severity = severity
        self.setting = setting
        self.observed = observed
        self.expected = expected
        self.owasp = owasp
        self.owasp_mcp = owasp_mcp
        self.owasp_agentic = owasp_agentic
        self.nist_800_53 = nist_800_53


_TOOL_RULES: tuple[_RuntimeRule, ...] = (
    _RuntimeRule(
        "MCP-TOOL-001",
        FindingType.INJECTION,
        FindingSource.MCP_SCAN,
        "Tool argument reaches a SQL statement without parameter binding",
        "The tool interpolates a caller-supplied argument into the statement it executes.",
        "Bind every caller-supplied value as a parameter and reject statements built by concatenation.",
        "high",
        setting="tool.arguments binding",
        observed="interpolated into the statement",
        expected="bound as a parameter",
        owasp=("LLM05",),
        owasp_mcp=("MCP05",),
        owasp_agentic=("ASI02",),
        nist_800_53=("SI-10",),
    ),
    _RuntimeRule(
        "MCP-TOOL-002",
        FindingType.TOOL_DRIFT,
        FindingSource.MCP_SCAN,
        "Tool description changed after approval",
        "The advertised description differs from the version the gateway policy was written against.",
        "Re-review the tool and re-approve it, or pin the gateway policy to the approved descriptor hash.",
        "medium",
        setting="tool.descriptor hash",
        observed="differs from the approved descriptor",
        expected="matches the approved descriptor",
        owasp=("LLM03",),
        owasp_mcp=("MCP03",),
        owasp_agentic=("ASI04",),
        nist_800_53=("CM-6",),
    ),
    _RuntimeRule(
        "MCP-TOOL-003",
        FindingType.RATE_LIMIT,
        FindingSource.MCP_SCAN,
        "Tool has no per-caller rate limit",
        "The gateway policy applies no call ceiling, so one agent can exhaust the downstream quota.",
        "Set a per-caller ceiling on the gateway policy for this tool.",
        "low",
        setting="gateway.rate_limit.per_caller",
        observed="unset",
        expected="a per-caller call ceiling",
        owasp=("LLM10",),
        owasp_mcp=("MCP02",),
        owasp_agentic=("ASI01",),
        nist_800_53=("AU-6",),
    ),
    _RuntimeRule(
        "GW-DATA-004",
        FindingType.EXFILTRATION,
        FindingSource.PROXY,
        "Write-capable tool returned regulated data to a model context",
        "Gateway evidence shows a response carrying PHI-classified columns forwarded to a model call.",
        "Scope the tool to read-only projections and enable response classification on the gateway policy.",
        "critical",
        setting="gateway.response_classification",
        observed="off; PHI columns forwarded",
        expected="on, blocking regulated columns",
        owasp=("LLM02",),
        owasp_mcp=("MCP10",),
        owasp_agentic=("ASI02",),
        nist_800_53=("AC-3",),
    ),
)


_IDENTITY_RULES: tuple[_RuntimeRule, ...] = (
    _RuntimeRule(
        "IAM-CIEM-005",
        FindingType.CIEM_OVER_PRIVILEGE,
        FindingSource.CLOUD_SECURITY,
        "Principal holds permissions it has never exercised",
        "Ninety days of audit evidence show none of the write actions this principal is granted.",
        "Right-size the attached policy to the actions observed, and re-review on a schedule.",
        "high",
        setting="policy.granted_actions",
        observed="write actions granted, none exercised in 90 days",
        expected="only the actions observed in use",
        owasp_agentic=("ASI03",),
        nist_800_53=("AC-6",),
    ),
)


_AI_RULES: tuple[_RuntimeRule, ...] = (
    _RuntimeRule(
        "AI-PROMPT-006",
        FindingType.PROMPT_SECURITY,
        FindingSource.PROMPT_SCAN,
        "System prompt embeds a data-access instruction with no guardrail",
        "The template instructs the model to retrieve records without naming a classification boundary.",
        "Move the retrieval boundary into the tool contract and attach a guardrail to the deployment.",
        "medium",
        setting="prompt.retrieval_boundary",
        observed="no classification boundary named",
        expected="the boundary declared in the tool contract",
        owasp=("LLM01", "LLM07"),
        owasp_agentic=("ASI01",),
        nist_800_53=("CM-7",),
    ),
    _RuntimeRule(
        "AI-MODEL-007",
        FindingType.MODEL_INTEGRITY,
        FindingSource.MODEL_SCAN,
        "Model artifact has no verifiable provenance",
        "The served artifact carries no signature or attestation linking it to a build.",
        "Publish and verify an attestation for the artifact before it is promoted to production.",
        "high",
        setting="artifact.attestation",
        observed="absent",
        expected="a verified build attestation",
        owasp=("LLM03",),
        owasp_agentic=("ASI04",),
        nist_800_53=("SR-4", "SI-7"),
    ),
)


class _DataRule:
    """A data-security-posture detection on an inventoried data asset.

    DSPM is the one posture lane a package scanner cannot reach: it is about
    what the data IS and who can read it, not what version something is pinned
    to. Each rule names the classification it acts on, so a finding says *why*
    the object is sensitive rather than asserting that it is.
    """

    __slots__ = (
        "rule_id",
        "finding_type",
        "resource_types",
        "title",
        "description",
        "remediation",
        "severity",
        "classification",
        "setting",
        "observed",
        "expected",
        "nist_800_53",
        "rate",
    )

    def __init__(
        self,
        rule_id: str,
        finding_type: FindingType,
        resource_types: tuple[str, ...],
        title: str,
        description: str,
        remediation: str,
        severity: str,
        *,
        classification: str,
        setting: str,
        observed: str,
        expected: str,
        nist_800_53: tuple[str, ...] = (),
        rate: int = 30,
    ) -> None:
        self.rule_id = rule_id
        self.finding_type = finding_type
        self.resource_types = resource_types
        self.title = title
        self.description = description
        self.remediation = remediation
        self.severity = severity
        self.classification = classification
        self.setting = setting
        self.observed = observed
        self.expected = expected
        self.nist_800_53 = nist_800_53
        # Percentage of matching assets that carry the finding. Not every table
        # in a warehouse is misgoverned; a lane where every asset fails reads as
        # a seeded constant rather than a posture result.
        self.rate = rate


_DATA_RULES: tuple[_DataRule, ...] = (
    _DataRule(
        "DSPM-PII-001",
        FindingType.SENSITIVE_DATA,
        ("table",),
        "Regulated columns readable without a masking policy",
        "The table holds columns classified as regulated health data and no masking policy is attached, "
        "so every role with SELECT reads them in the clear.",
        "Attach a masking policy to the classified columns and grant unmasked access through a separate, reviewed role.",
        "critical",
        classification="phi",
        setting="table.masking_policy",
        observed="absent on classified columns",
        expected="a masking policy bound to every classified column",
        nist_800_53=("AC-3", "SC-28"),
        rate=26,
    ),
    _DataRule(
        "DSPM-SHARE-002",
        FindingType.SENSITIVE_DATA,
        ("share",),
        "Share exposes a classified object outside the account boundary",
        "An outbound share includes an object carrying regulated data, which places it beyond the account's own access review.",
        "Remove the classified object from the share, or replace it with a view that projects only non-regulated columns.",
        "high",
        classification="phi",
        setting="share.objects",
        observed="a classified object is in scope",
        expected="only non-regulated projections are shared",
        nist_800_53=("AC-21",),
        rate=22,
    ),
    _DataRule(
        "DSPM-STAGE-003",
        FindingType.SENSITIVE_DATA,
        ("stage",),
        "Stage retains unencrypted extracts of regulated data",
        "Files staged for load or unload persist after the operation with no server-side encryption declared.",
        "Declare server-side encryption on the stage and expire staged files once the load completes.",
        "high",
        classification="pii",
        setting="stage.encryption",
        observed="unset; extracts persist",
        expected="server-side encryption with an expiry policy",
        nist_800_53=("SC-28", "SI-12"),
        rate=24,
    ),
    _DataRule(
        "DSPM-RETAIN-004",
        FindingType.SENSITIVE_DATA,
        ("database",),
        "Regulated schema has no retention boundary",
        "The database holds regulated data with time travel and no declared retention limit, "
        "so deleted rows remain recoverable indefinitely.",
        "Set a data retention period appropriate to the classification and record the basis for it.",
        "medium",
        classification="phi",
        setting="database.data_retention_time_in_days",
        observed="unbounded",
        expected="a retention window justified by the classification",
        nist_800_53=("SI-12",),
        rate=20,
    ),
    _DataRule(
        "DSPM-ACCESS-005",
        FindingType.SENSITIVE_DATA,
        ("table",),
        "Non-human identity reads regulated data with no access review",
        "A service role holds SELECT on classified columns and appears in no completed access review for the period.",
        "Bring the role into the access-review cycle and scope its grant to the columns it actually reads.",
        "high",
        classification="phi",
        setting="grants.reviewed_at",
        observed="no review recorded",
        expected="a completed review within the cycle",
        nist_800_53=("AC-6", "AU-6"),
        rate=18,
    ),
)
