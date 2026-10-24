"""Terraform security rules for AWS identity, keys, secrets, logging and detection."""

from __future__ import annotations

import re

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource

_CLOUDWATCH_LOG_RE = re.compile(
    r"(?:enabled_cloudwatch_logs_exports|logging\s*\{|aws_cloudwatch_log_group)",
    re.IGNORECASE,
)
_SSH_KEY_INLINE_RE = re.compile(
    r"(?:public_key|private_key|ssh_key|key_material)\s*=\s*"
    r'"(ssh-rsa\s|ssh-ed25519\s|-----BEGIN)',
    re.IGNORECASE,
)

# TF-SEC-013: CloudWatch log group retention
_RETENTION_RE = re.compile(r"retention_in_days\s*=\s*(\d+)", re.IGNORECASE)

# TF-SEC-019: API Gateway access logging
_ACCESS_LOG_SETTINGS_RE = re.compile(r"access_log_settings\s*\{", re.IGNORECASE)

# TF-SEC-020: KMS key rotation
_KEY_ROTATION_RE = re.compile(r"enable_key_rotation\s*=\s*true", re.IGNORECASE)

# TF-SEC-031: CloudTrail multi-region
_IS_MULTI_REGION_RE = re.compile(r"is_multi_region_trail\s*=\s*true", re.IGNORECASE)

# TF-SEC-032: CloudTrail log file validation
_LOG_FILE_VALIDATION_RE = re.compile(r"enable_log_file_validation\s*=\s*true", re.IGNORECASE)

# TF-SEC-033/034: SNS/SQS encryption
_KMS_MASTER_KEY_RE = re.compile(r"kms_master_key_id\s*=", re.IGNORECASE)

# TF-SEC-039: Secrets Manager KMS
_SECRETS_KMS_RE = re.compile(r"kms_key_id\s*=", re.IGNORECASE)

# TF-SEC-040: SSM SecureString plaintext
_SSM_VALUE_RE = re.compile(r'type\s*=\s*"SecureString"', re.IGNORECASE)
_SSM_KEY_ID_RE = re.compile(r"key_id\s*=", re.IGNORECASE)


def _wildcard_list(value: str) -> str:
    quoted = '"(?:' + value + ')"'
    return "(?:" + quoted + r"|\[[^\]]*" + quoted + r"[^\]]*\])"


# JSON heredoc/file policies ("Action": "*"), jsonencode HCL (Action = "*") and
# aws_iam_policy_document statements (actions = ["*"]). ``*:*`` is the same
# grant as ``*``. The quote/word boundary keeps NotAction/NotResource out.
_ACTION_KEY = r'(?:"Action"\s*:|\bAction\s*=|\bactions\s*=)\s*'
_RESOURCE_KEY = r'(?:"Resource"\s*:|\bResource\s*=|\bresources\s*=)\s*'
_IAM_STAR_ACTION_RE = re.compile(_ACTION_KEY + _wildcard_list(r"\*(?::\*)?"))
_IAM_STAR_RESOURCE_RE = re.compile(_RESOURCE_KEY + _wildcard_list(r"\*"))
# TF-SEC-010: every action of one service (``s3:*``, ``iam:*``).
_IAM_SERVICE_STAR_ACTION_RE = re.compile(_ACTION_KEY + _wildcard_list(r"[A-Za-z0-9-]+:\*"))
_DENY_EFFECT_RE = re.compile(r'(?:"Effect"\s*:|\b[Ee]ffect\s*=)\s*"Deny"')


def _enclosing_statement(block: str, pos: int) -> str:
    """Return the innermost ``{...}`` object around ``pos`` (one IAM statement)."""
    depth = 0
    start = 0
    for index in range(pos - 1, -1, -1):
        char = block[index]
        if char == "}":
            depth += 1
        elif char == "{":
            if depth == 0:
                start = index
                break
            depth -= 1
    depth = 0
    end = len(block)
    for index in range(pos, len(block)):
        char = block[index]
        if char == "{":
            depth += 1
        elif char == "}":
            if depth == 0:
                end = index
                break
            depth -= 1
    return block[start:end]


def _granting_matches(pattern: re.Pattern[str], res: TfResource) -> list[int]:
    """Lines of ``pattern`` matches that sit in an Allow (not Deny) statement."""
    lines: list[int] = []
    for match in pattern.finditer(res.block):
        if _DENY_EFFECT_RE.search(_enclosing_statement(res.block, match.start())):
            continue
        lines.append(res.block_start_line + res.block[: match.start()].count("\n"))
    return lines


def _iam_finding(res: TfResource, *, rule_id: str, severity: str, title: str, message: str, line: int) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=res.rel_path,
        line_number=line,
        category="terraform",
        compliance=["CIS-AWS-1.16", "NIST-AC-6"],
    )


def tf_sec_004(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-004: IAM policy granting every action (``*``/``*:*``) or every resource."""
    findings: list[IaCFinding] = []
    for line in _granting_matches(_IAM_STAR_ACTION_RE, res):
        findings.append(
            _iam_finding(
                res,
                rule_id="TF-SEC-004",
                severity="high",
                title='IAM policy with Action: "*"',
                message=(
                    f"IAM policy '{res.rname}' grants Action: \"*\". "
                    "Follow least-privilege: scope actions to specific services and operations."
                ),
                line=line,
            )
        )
    for line in _granting_matches(_IAM_STAR_RESOURCE_RE, res):
        findings.append(
            _iam_finding(
                res,
                rule_id="TF-SEC-004",
                severity="high",
                title='IAM policy with Resource: "*"',
                message=f"IAM policy '{res.rname}' grants Resource: \"*\". Scope resources to specific ARNs.",
                line=line,
            )
        )
    return findings


def tf_sec_006(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-006: CloudWatch logging."""
    rtype, rname, block, block_start_line, rel_path = res.rtype, res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _CLOUDWATCH_LOG_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-006",
                severity="low",
                title="CloudWatch logging not enabled",
                message=(
                    f"Resource '{rname}' ({rtype}) does not configure "
                    "CloudWatch log exports. Enable logging for audit "
                    "and incident response."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-3.1", "NIST-AU-2"],
            )
        )
    return findings


def tf_sec_007(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-007: Hardcoded SSH key."""
    rtype, rname, block, block_start_line, rel_path = res.rtype, res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    ssh_m = _SSH_KEY_INLINE_RE.search(block)
    if ssh_m:
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-007",
                severity="high",
                title="Hardcoded SSH key",
                message=(
                    f"Resource '{rname}' ({rtype}) contains a hardcoded SSH key. "
                    "Store keys in a secrets manager or use file() with a "
                    "gitignored key file."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-1.14", "NIST-IA-5"],
            )
        )
    return findings


def tf_sec_010(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-010: IAM policy granting every action of a service (``s3:*``)."""
    return [
        _iam_finding(
            res,
            rule_id="TF-SEC-010",
            severity="medium",
            title="IAM policy with service-wide wildcard action",
            message=f"IAM policy '{res.rname}' grants every action of a service (for example \"s3:*\"). "
            "Scope actions to the specific operations the principal needs.",
            line=line,
        )
        for line in _granting_matches(_IAM_SERVICE_STAR_ACTION_RE, res)
    ]


def tf_sec_013(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-013: CloudWatch log group without retention."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    retention_m = _RETENTION_RE.search(block)
    if not retention_m:
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-013",
                severity="low",
                title="CloudWatch log group without retention",
                message=(
                    f"CloudWatch log group '{rname}' does not set "
                    "retention_in_days. Logs will be retained indefinitely, "
                    "increasing costs. Set a retention period."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-3.1", "NIST-AU-11"],
            )
        )
    return findings


def tf_sec_019(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-019: API Gateway without access logging."""
    rtype, rname, block, block_start_line, rel_path = res.rtype, res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _ACCESS_LOG_SETTINGS_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-019",
                severity="low",
                title="API Gateway without access logging",
                message=(
                    f"API Gateway stage '{rname}' ({rtype}) does not have "
                    "an access_log_settings block. Enable access logging "
                    "for API monitoring and compliance."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["NIST-AU-2", "NIST-SI-4"],
            )
        )
    return findings


def tf_sec_020(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-020: KMS key without rotation."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _KEY_ROTATION_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-020",
                severity="medium",
                title="KMS key without rotation",
                message=(
                    f"KMS key '{rname}' does not set "
                    "enable_key_rotation = true. Enable automatic key "
                    "rotation to reduce risk of key compromise."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-3.8", "NIST-SC-12"],
            )
        )
    return findings


def tf_sec_031(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-031: CloudTrail not enabled for all regions."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _IS_MULTI_REGION_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-031",
                severity="high",
                title="CloudTrail not enabled for all regions",
                message=(
                    f"CloudTrail '{rname}' does not have "
                    "is_multi_region_trail = true. Enable multi-region "
                    "trailing to capture API calls in all AWS regions."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-3.1", "NIST-AU-2"],
            )
        )
    return findings


def tf_sec_032(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-032: CloudTrail log file validation disabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _LOG_FILE_VALIDATION_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-032",
                severity="medium",
                title="CloudTrail log file validation disabled",
                message=(
                    f"CloudTrail '{rname}' does not have "
                    "enable_log_file_validation = true. Enable log file "
                    "validation to detect tampering of log files."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-3.2", "NIST-AU-9"],
            )
        )
    return findings


def tf_sec_033(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-033: SNS topic not encrypted."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _KMS_MASTER_KEY_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-033",
                severity="medium",
                title="SNS topic not encrypted",
                message=(
                    f"SNS topic '{rname}' does not have "
                    "kms_master_key_id set. Enable server-side encryption "
                    "with a KMS key to protect messages at rest."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.5", "NIST-SC-28"],
            )
        )
    return findings


def tf_sec_034(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-034: SQS queue not encrypted."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _KMS_MASTER_KEY_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-034",
                severity="medium",
                title="SQS queue not encrypted",
                message=(
                    f"SQS queue '{rname}' does not have "
                    "kms_master_key_id set. Enable server-side encryption "
                    "with a KMS key to protect messages at rest."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-2.6", "NIST-SC-28"],
            )
        )
    return findings


def tf_sec_039(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-039: Secrets Manager secret without KMS encryption."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if not _SECRETS_KMS_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-039",
                severity="medium",
                title="Secrets Manager secret without KMS encryption",
                message=(
                    f"Secrets Manager secret '{rname}' does not set "
                    "kms_key_id. Without a customer-managed KMS key, "
                    "the secret is encrypted with the default AWS key. "
                    "Use a CMK for better key management and audit trail."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["NIST-SC-12", "NIST-SC-28"],
            )
        )
    return findings


def tf_sec_040(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-040: SSM Parameter with plaintext SecureString."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    if _SSM_VALUE_RE.search(block) and not _SSM_KEY_ID_RE.search(block):
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-040",
                severity="medium",
                title="SSM SecureString without CMK encryption",
                message=(
                    f"SSM parameter '{rname}' is a SecureString but does "
                    "not specify key_id for a customer-managed KMS key. "
                    "Use a CMK for enhanced encryption control."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["NIST-SC-12", "NIST-SC-28"],
            )
        )
    return findings


def tf_sec_050(res: TfResource) -> list[IaCFinding]:
    """TF-SEC-050: GuardDuty not enabled."""
    rname, block, block_start_line, rel_path = res.rname, res.block, res.block_start_line, res.rel_path
    findings: list[IaCFinding] = []
    # Check if enable is explicitly set to false
    enable_false_m = re.search(r"enable\s*=\s*false", block, re.IGNORECASE)
    if enable_false_m:
        findings.append(
            IaCFinding(
                rule_id="TF-SEC-050",
                severity="high",
                title="GuardDuty detector disabled",
                message=(
                    f"GuardDuty detector '{rname}' has enable = false. "
                    "Enable GuardDuty for continuous threat detection "
                    "and monitoring of malicious activity."
                ),
                file_path=rel_path,
                line_number=block_start_line,
                category="terraform",
                compliance=["CIS-AWS-4.1", "NIST-SI-4"],
            )
        )
    return findings
