"""Terraform security misconfiguration scanner.

Complements the existing ``terraform.py`` AI resource discovery module by
adding **security-focused** misconfig rules for AWS/cloud resources against
**cloud provider official documentation and best practices**:

- AWS Well-Architected Framework (Security Pillar)
- AWS Security Best Practices (SEC01-SEC11)
- CIS AWS Foundations Benchmark v2.0

Rules are mapped to applicable compliance frameworks (CIS-AWS, NIST SP 800-53)
where the mapping is well-established.  Uses regex-based scanning of ``.tf``
files — same approach as ``terraform.py``, no HCL parser needed.

Rules
-----
TF-SEC-001  S3 bucket without encryption (AWS SEC08, CIS 2.1.1)
TF-SEC-002  S3 bucket (or aws_s3_bucket_acl) with public ACL (AWS SEC01, CIS 2.1.2)
TF-SEC-003  Security group with 0.0.0.0/0 ingress on non-443/80 port (CIS 5.2)
TF-SEC-004  IAM policy/policy document with Action * (or *:*) or Resource * (AWS SEC03, CIS 1.16)
TF-SEC-005  RDS without encryption (AWS SEC08, CIS 2.3.1)
TF-SEC-006  CloudWatch logging not enabled (AWS SEC04, CIS 3.1)
TF-SEC-007  SSH key hardcoded in resource, any provider (AWS SEC02, CIS AWS 1.14 on aws_ only)
TF-SEC-008  Retired: duplicated TF-SEC-001 on the same bucket line
TF-SEC-009  Security group rule with 0.0.0.0/0 (CIS 5.2)
TF-SEC-010  IAM policy with service-wide wildcard action, e.g. s3:* (AWS SEC03, CIS 1.16)
TF-SEC-011  RDS without storage encryption (AWS SEC08, CIS 2.3.1)
TF-SEC-012  EC2 instance without IMDSv2 (AWS SEC01, CIS 5.6)
TF-SEC-013  CloudWatch log group without retention (AWS SEC04, CIS 3.1)
TF-SEC-014  VPC without flow logs (AWS SEC04, CIS 3.9)
TF-SEC-015  EKS cluster without envelope encryption (AWS SEC08)
TF-SEC-016  Lambda without dead letter queue (AWS SEC05)
TF-SEC-017  ElastiCache without encryption in transit (AWS SEC08)
TF-SEC-018  DynamoDB without point-in-time recovery (AWS SEC08, CIS 2.4)
TF-SEC-019  API Gateway without access logging (AWS SEC04)
TF-SEC-020  KMS key without rotation (AWS SEC08, CIS 3.8)
TF-SEC-021  S3 bucket versioning not enabled (AWS SEC08, CIS 2.1.3)
TF-SEC-022  S3 public access block missing or with a flag set to false (AWS SEC01, CIS 2.1.5)
TF-SEC-023  S3 bucket logging not enabled (AWS SEC04, CIS 3.6)
TF-SEC-024  RDS public accessibility enabled (AWS SEC01, CIS 2.3.2)
TF-SEC-025  RDS backup retention period < 7 days (AWS SEC08, CIS 2.3.3)
TF-SEC-026  RDS multi-AZ not enabled (AWS SEC08)
TF-SEC-027  EBS volume not encrypted (AWS SEC08, CIS 2.2.1)
TF-SEC-028  EBS snapshot not encrypted (AWS SEC08)
TF-SEC-029  ALB/ELB access logging not enabled (AWS SEC04, CIS 3.10)
TF-SEC-030  ALB/NLB deletion protection disabled (AWS SEC05)
TF-SEC-031  CloudTrail not enabled for all regions (AWS SEC04, CIS 3.1)
TF-SEC-032  CloudTrail log file validation disabled (AWS SEC04, CIS 3.2)
TF-SEC-033  SNS topic not encrypted (AWS SEC08, CIS 2.5)
TF-SEC-034  SQS queue not encrypted (AWS SEC08, CIS 2.6)
TF-SEC-035  ECR repository scan on push disabled (AWS SEC01)
TF-SEC-036  ECR repository image tag mutability enabled (AWS SEC01)
TF-SEC-037  ECS task definition with host networking (AWS SEC01)
TF-SEC-038  ECS task definition running as root (AWS SEC03)
TF-SEC-039  Secrets Manager secret without KMS encryption (AWS SEC08)
TF-SEC-040  SSM Parameter with plaintext SecureString (AWS SEC08)
TF-SEC-041  VPC default security group allows traffic (AWS SEC01, CIS 5.3)
TF-SEC-042  RDS instance without deletion protection (AWS SEC05)
TF-SEC-043  Elasticsearch/OpenSearch without encryption at rest (AWS SEC08)
TF-SEC-044  Elasticsearch/OpenSearch without node-to-node encryption (AWS SEC08)
TF-SEC-045  Lambda function without VPC configuration (AWS SEC01)
TF-SEC-046  Lambda environment variables with sensitive values (AWS SEC02)
TF-SEC-047  Redshift cluster without encryption (AWS SEC08, CIS 2.7)
TF-SEC-048  Redshift cluster publicly accessible (AWS SEC01)
TF-SEC-049  WAF not associated with ALB/CloudFront (AWS SEC05)
TF-SEC-050  GuardDuty not enabled (AWS SEC04, CIS 4.1)
TF-SEC-051  Hardcoded secret in a resource argument, any provider (NIST IA-5; CIS AWS 1.14 on aws_ only)

Azure (azurerm_*; CIS Microsoft Azure Foundations IDs as used by the live benchmark)
TF-SEC-101  Storage account / container allows anonymous public blob access (CIS Azure 3.7)
TF-SEC-102  Storage account does not require HTTPS (CIS Azure 3.1)
TF-SEC-103  Storage account minimum TLS below 1.2 (CIS Azure 3.15)
TF-SEC-104  NSG rule allows inbound traffic from any internet source (CIS Azure 6.1 RDP / 6.2 SSH / 6.4 UDP)
TF-SEC-105  Database server allows public network access (CIS Azure 4.1.6 on SQL)
TF-SEC-106  Database server does not enforce SSL / TLS 1.2 (CIS Azure 4.2.2 MySQL, 4.3.1 PostgreSQL)
TF-SEC-107  Key Vault without purge protection (CIS Azure 8.3)
TF-SEC-108  Managed disk without customer-managed key encryption (CIS Azure 7.3)
TF-SEC-109  Network interface attaches a public IP (NIST SC-7)
TF-SEC-110  NSG flow log disabled or retained < 90 days (NIST AU-12)
TF-SEC-111  SQL server without an extended auditing policy (CIS Azure 4.1.1)
TF-SEC-112  SQL database with Transparent Data Encryption disabled (CIS Azure 4.1.2)

GCP (google_*; CIS Google Cloud Platform Foundation IDs as used by the live benchmark)
TF-SEC-201  Bucket IAM grants allUsers / allAuthenticatedUsers (CIS GCP 5.1)
TF-SEC-202  Bucket without uniform bucket-level access (CIS GCP 5.2)
TF-SEC-203  Firewall allows ingress from 0.0.0.0/0 or ::/0 (CIS GCP 3.6 SSH / 3.7 RDP / 3.8 ICMP)
TF-SEC-204  Cloud SQL instance with a public IP (CIS GCP 6.2)
TF-SEC-205  Cloud SQL instance does not require SSL (CIS GCP 6.1)
TF-SEC-206  Cloud SQL instance without automated backups (CIS GCP 6.3)
TF-SEC-207  Compute instance with an external IP (CIS GCP 4.9)
TF-SEC-208  OS Login disabled via instance or project metadata (CIS GCP 4.4)
TF-SEC-209  Serial console enabled via metadata (CIS GCP 4.5)
TF-SEC-210  Subnetwork without VPC flow logs (CIS GCP 3.9)
TF-SEC-211  Compute instance with IP forwarding enabled (CIS GCP 4.6)
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.iac import terraform_security_azure_data as _azure_data
from agent_bom.iac import terraform_security_azure_network as _azure_network
from agent_bom.iac import terraform_security_azure_storage as _azure_storage
from agent_bom.iac import terraform_security_database as _database
from agent_bom.iac import terraform_security_gcp_compute as _gcp_compute
from agent_bom.iac import terraform_security_gcp_storage_sql as _gcp_storage_sql
from agent_bom.iac import terraform_security_identity as _identity
from agent_bom.iac import terraform_security_network as _network
from agent_bom.iac import terraform_security_secrets as _secrets
from agent_bom.iac import terraform_security_storage as _storage
from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfCheck, TfResource, extract_block, line_number

_RESOURCE_RE = re.compile(r'^(resource|data)\s+"([a-zA-Z][a-zA-Z0-9_]+)"\s+"([^"]+)"', re.MULTILINE)
_IAM_POLICY_TYPES = frozenset({"aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy", "aws_iam_user_policy"})
# Data sources are not deployed resources; only these are evaluated.
_DATA_CHECKS: dict[str, tuple[TfCheck, ...]] = {
    "aws_iam_policy_document": (_identity.tf_sec_004, _identity.tf_sec_010),
}

# Emission order is rule order; ``None`` scopes a rule to every resource type.
_RULES: tuple[tuple[frozenset[str] | None, TfCheck], ...] = (
    (frozenset({"aws_s3_bucket"}), _storage.tf_sec_001_002),
    (frozenset({"aws_security_group"}), _network.tf_sec_003),
    (_IAM_POLICY_TYPES, _identity.tf_sec_004),
    (frozenset({"aws_db_instance", "aws_rds_cluster"}), _database.tf_sec_005),
    (frozenset({"aws_db_instance", "aws_rds_cluster", "aws_elasticsearch_domain"}), _identity.tf_sec_006),
    (None, _identity.tf_sec_007),
    (frozenset({"aws_security_group_rule"}), _network.tf_sec_009),
    (_IAM_POLICY_TYPES, _identity.tf_sec_010),
    (frozenset({"aws_db_instance", "aws_rds_cluster"}), _database.tf_sec_011),
    (frozenset({"aws_instance"}), _network.tf_sec_012),
    (frozenset({"aws_cloudwatch_log_group"}), _identity.tf_sec_013),
    (frozenset({"aws_vpc"}), _network.tf_sec_014),
    (frozenset({"aws_eks_cluster"}), _network.tf_sec_015),
    (frozenset({"aws_lambda_function"}), _network.tf_sec_016),
    (frozenset({"aws_elasticache_replication_group", "aws_elasticache_cluster"}), _database.tf_sec_017),
    (frozenset({"aws_dynamodb_table"}), _storage.tf_sec_018),
    (frozenset({"aws_api_gateway_stage", "aws_apigatewayv2_stage"}), _identity.tf_sec_019),
    (frozenset({"aws_kms_key"}), _identity.tf_sec_020),
    (frozenset({"aws_s3_bucket"}), _storage.tf_sec_021),
    (frozenset({"aws_s3_bucket"}), _storage.tf_sec_022),
    (frozenset({"aws_s3_bucket_public_access_block"}), _storage.tf_sec_022_flags),
    (frozenset({"aws_s3_bucket_acl"}), _storage.tf_sec_002_acl_resource),
    (frozenset({"aws_s3_bucket"}), _storage.tf_sec_023),
    (frozenset({"aws_db_instance", "aws_rds_cluster"}), _database.tf_sec_024),
    (frozenset({"aws_db_instance", "aws_rds_cluster"}), _database.tf_sec_025),
    (frozenset({"aws_db_instance"}), _database.tf_sec_026),
    (frozenset({"aws_ebs_volume"}), _storage.tf_sec_027),
    (frozenset({"aws_ebs_snapshot"}), _storage.tf_sec_028),
    (frozenset({"aws_lb", "aws_alb", "aws_elb"}), _network.tf_sec_029),
    (frozenset({"aws_lb", "aws_alb"}), _network.tf_sec_030),
    (frozenset({"aws_cloudtrail"}), _identity.tf_sec_031),
    (frozenset({"aws_cloudtrail"}), _identity.tf_sec_032),
    (frozenset({"aws_sns_topic"}), _identity.tf_sec_033),
    (frozenset({"aws_sqs_queue"}), _identity.tf_sec_034),
    (frozenset({"aws_ecr_repository"}), _network.tf_sec_035),
    (frozenset({"aws_ecr_repository"}), _network.tf_sec_036),
    (frozenset({"aws_ecs_task_definition"}), _network.tf_sec_037),
    (frozenset({"aws_ecs_task_definition"}), _network.tf_sec_038),
    (frozenset({"aws_secretsmanager_secret"}), _identity.tf_sec_039),
    (frozenset({"aws_ssm_parameter"}), _identity.tf_sec_040),
    (frozenset({"aws_default_security_group"}), _network.tf_sec_041),
    (frozenset({"aws_db_instance", "aws_rds_cluster"}), _database.tf_sec_042),
    (frozenset({"aws_elasticsearch_domain", "aws_opensearch_domain"}), _database.tf_sec_043),
    (frozenset({"aws_elasticsearch_domain", "aws_opensearch_domain"}), _database.tf_sec_044),
    (frozenset({"aws_lambda_function"}), _network.tf_sec_045),
    (frozenset({"aws_lambda_function"}), _network.tf_sec_046),
    (frozenset({"aws_redshift_cluster"}), _database.tf_sec_047),
    (frozenset({"aws_redshift_cluster"}), _database.tf_sec_048),
    (frozenset({"aws_lb", "aws_alb", "aws_cloudfront_distribution"}), _network.tf_sec_049),
    (frozenset({"aws_guardduty_detector"}), _identity.tf_sec_050),
    (None, _secrets.tf_sec_051),
    # Azure
    (frozenset({"azurerm_storage_account", "azurerm_storage_container"}), _azure_storage.tf_sec_101),
    (frozenset({"azurerm_storage_account"}), _azure_storage.tf_sec_102),
    (frozenset({"azurerm_storage_account"}), _azure_storage.tf_sec_103),
    (frozenset({"azurerm_network_security_rule", "azurerm_network_security_group"}), _azure_network.tf_sec_104),
    (_azure_data.AZURE_DB_SERVER_TYPES, _azure_data.tf_sec_105),
    (_azure_data.AZURE_SINGLE_SERVER_TYPES | {"azurerm_mssql_server"}, _azure_data.tf_sec_106),
    (frozenset({"azurerm_key_vault"}), _azure_data.tf_sec_107),
    (frozenset({"azurerm_managed_disk"}), _azure_data.tf_sec_108),
    (frozenset({"azurerm_network_interface"}), _azure_network.tf_sec_109),
    (frozenset({"azurerm_network_watcher_flow_log"}), _azure_network.tf_sec_110),
    (frozenset({"azurerm_mssql_server"}), _azure_data.tf_sec_111),
    (frozenset({"azurerm_mssql_database"}), _azure_data.tf_sec_112),
    # GCP
    (_gcp_storage_sql.GCS_IAM_TYPES, _gcp_storage_sql.tf_sec_201),
    (frozenset({"google_storage_bucket"}), _gcp_storage_sql.tf_sec_202),
    (frozenset({"google_compute_firewall"}), _gcp_compute.tf_sec_203),
    (frozenset({"google_sql_database_instance"}), _gcp_storage_sql.tf_sec_204),
    (frozenset({"google_sql_database_instance"}), _gcp_storage_sql.tf_sec_205),
    (frozenset({"google_sql_database_instance"}), _gcp_storage_sql.tf_sec_206),
    (frozenset({"google_compute_instance"}), _gcp_compute.tf_sec_207),
    (_gcp_compute.GCE_METADATA_TYPES, _gcp_compute.tf_sec_208),
    (frozenset({"google_compute_instance"}), _gcp_compute.tf_sec_209),
    (frozenset({"google_compute_subnetwork"}), _gcp_compute.tf_sec_210),
    (frozenset({"google_compute_instance"}), _gcp_compute.tf_sec_211),
)


def _build_dispatch() -> dict[str, tuple[TfCheck, ...]]:
    rtypes = {rtype for scope, _ in _RULES if scope is not None for rtype in scope}
    return {rtype: tuple(check for scope, check in _RULES if scope is None or rtype in scope) for rtype in sorted(rtypes)}


_CHECKS_BY_TYPE = _build_dispatch()
_GENERIC_CHECKS: tuple[TfCheck, ...] = tuple(check for scope, check in _RULES if scope is None)


def _blank_block_comment(m: re.Match[str]) -> str:
    return "\n" * m.group(0).count("\n")


def _strip_comments(raw_content: str) -> str:
    """Neutralise HCL comments to prevent false positives from commented-out blocks.

    Comment text is blanked rather than deleted so character offsets — and
    therefore ``line_number()`` results — stay correct.
    """
    content = re.sub(r"/\*.*?\*/", _blank_block_comment, raw_content, flags=re.DOTALL)
    content = re.sub(r"(?m)#.*$", "", content)
    return re.sub(r"(?m)//.*$", "", content)


def scan_terraform_security(file_path: str | Path) -> list[IaCFinding]:
    """Scan a single .tf file for security misconfigurations.

    Parameters
    ----------
    file_path:
        Path to a Terraform file.

    Returns
    -------
    list[IaCFinding]
        Detected security misconfigurations.
    """
    path = Path(file_path)
    if not path.is_file() or path.suffix != ".tf":
        return []

    content = _strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    rel_path = str(path)
    findings: list[IaCFinding] = []

    for m in _RESOURCE_RE.finditer(content):
        brace_pos = content.find("{", m.end())
        if brace_pos == -1:
            continue
        block_kind, rtype = m.group(1), m.group(2)
        if block_kind == "data" and rtype not in _DATA_CHECKS:
            continue
        resource = TfResource(
            rtype=rtype,
            rname=m.group(3),
            block=extract_block(content, brace_pos + 1),
            block_start_line=line_number(content, m.start()),
            rel_path=rel_path,
            content=content,
            block_offset=brace_pos + 1,
        )
        checks = _DATA_CHECKS[rtype] if block_kind == "data" else _CHECKS_BY_TYPE.get(rtype, _GENERIC_CHECKS)
        for check in checks:
            findings.extend(check(resource))

    return findings
