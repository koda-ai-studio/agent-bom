"""MITRE ATT&CK technique mapping for IaC misconfigurations.

Maps IaC security findings to the ATT&CK techniques that the misconfiguration
enables an attacker to execute. This provides "so what?" context: not just
"your S3 bucket is unencrypted" but "this enables T1530 Data from Cloud Storage."
"""

from __future__ import annotations

# Rule ID prefix → list of ATT&CK technique IDs
# Organized by IaC category (Terraform, Dockerfile, K8s, CloudFormation, Helm)

IAC_ATTACK_MAP: dict[str, list[str]] = {
    # ── Terraform (AWS) ─────────────────────────────────────────────────────
    # Encryption / Data Protection
    "TF-SEC-001": ["T1530"],  # S3 without encryption → Data from Cloud Storage
    "TF-SEC-005": ["T1530", "T1565"],  # RDS without encryption → Data Manipulation
    "TF-SEC-011": ["T1530"],  # RDS without storage encryption
    "TF-SEC-017": ["T1557"],  # ElastiCache no transit encryption → Adversary-in-the-Middle
    "TF-SEC-027": ["T1530"],  # EBS not encrypted
    "TF-SEC-028": ["T1530"],  # EBS snapshot not encrypted
    "TF-SEC-033": ["T1530"],  # SNS not encrypted
    "TF-SEC-034": ["T1530"],  # SQS not encrypted
    "TF-SEC-043": ["T1530"],  # Elasticsearch no encryption at rest
    "TF-SEC-044": ["T1557"],  # Elasticsearch no node-to-node encryption
    "TF-SEC-047": ["T1530"],  # Redshift without encryption
    # Public Access / Network Exposure
    "TF-SEC-002": ["T1190", "T1530"],  # S3 public ACL → Exploit Public-Facing App
    "TF-SEC-003": ["T1190"],  # SG 0.0.0.0/0 ingress
    "TF-SEC-009": ["T1190"],  # SG rule 0.0.0.0/0
    "TF-SEC-022": ["T1190", "T1530"],  # S3 public access block missing
    "TF-SEC-024": ["T1190"],  # RDS publicly accessible
    "TF-SEC-041": ["T1190"],  # VPC default SG allows traffic
    "TF-SEC-048": ["T1190"],  # Redshift publicly accessible
    # IAM / Privilege Escalation
    "TF-SEC-004": ["T1078", "T1098"],  # IAM wildcard → Valid Accounts + Account Manipulation
    "TF-SEC-010": ["T1078", "T1098"],  # IAM service-wide wildcard actions
    "TF-SEC-012": ["T1552.005"],  # EC2 no IMDSv2 → Cloud Instance Metadata API
    # Credential Exposure
    "TF-SEC-007": ["T1552.004"],  # SSH key hardcoded → Private Keys
    "TF-SEC-039": ["T1552.001"],  # Secrets Manager no KMS → Credentials In Files
    "TF-SEC-040": ["T1552.001"],  # SSM plaintext SecureString
    "TF-SEC-046": ["T1552.001"],  # Lambda env vars with sensitive values
    "TF-SEC-051": ["T1552.001"],  # Hardcoded secret in a resource argument
    # Logging / Detection Evasion
    "TF-SEC-006": ["T1562.008"],  # CloudWatch not enabled → Disable Cloud Logs
    "TF-SEC-013": ["T1562.008"],  # CloudWatch no retention
    "TF-SEC-014": ["T1562.008"],  # VPC no flow logs
    "TF-SEC-019": ["T1562.008"],  # API Gateway no access logging
    "TF-SEC-023": ["T1562.008"],  # S3 logging not enabled
    "TF-SEC-029": ["T1562.008"],  # ALB no access logging
    "TF-SEC-031": ["T1562.008"],  # CloudTrail not all regions
    "TF-SEC-032": ["T1562.008"],  # CloudTrail log validation disabled
    "TF-SEC-050": ["T1562.008"],  # GuardDuty not enabled
    # Key Management
    "TF-SEC-020": ["T1588.004"],  # KMS no rotation → Obtain Capabilities: Digital Certificates
    # Container Security
    "TF-SEC-035": ["T1525"],  # ECR scan on push disabled → Implant Internal Image
    "TF-SEC-036": ["T1525"],  # ECR tag mutability → Implant Internal Image
    "TF-SEC-037": ["T1610"],  # ECS host networking → Deploy Container
    "TF-SEC-038": ["T1611"],  # ECS running as root → Escape to Host
    # Availability
    "TF-SEC-018": ["T1485"],  # DynamoDB no PITR → Data Destruction
    "TF-SEC-025": ["T1485"],  # RDS backup retention < 7 days
    "TF-SEC-030": ["T1485"],  # ALB/NLB no deletion protection
    "TF-SEC-042": ["T1485"],  # RDS no deletion protection
    "TF-SEC-049": ["T1190"],  # WAF not associated
    # Version Control
    "TF-SEC-021": ["T1485", "T1565"],  # S3 versioning not enabled
    # Network Isolation
    "TF-SEC-045": ["T1610"],  # Lambda no VPC
    "TF-SEC-015": ["T1530"],  # EKS no envelope encryption
    # ── Dockerfile ──────────────────────────────────────────────────────────
    "DOCKER-001": ["T1525"],  # :latest / untagged base → Implant Internal Image
    "DOCKER-002": ["T1611"],  # Runs as root → Escape to Host
    "DOCKER-003": ["T1552.001"],  # Secret in ENV → Credentials In Files
    "DOCKER-005": ["T1105"],  # curl | sh → Ingress Tool Transfer
    "DOCKER-008": ["T1021.004"],  # SSH exposed → Remote Services: SSH
    "DOCKER-009": ["T1552.001"],  # COPY . . without .dockerignore
    "DOCKER-010": ["T1525"],  # Base not pinned by digest
    "DOCKER-011": ["T1611"],  # Root-owned copied files
    "DOCKER-012": ["T1222.002"],  # chmod 777 → Linux Permissions Modification
    "DOCKER-014": ["T1548.003"],  # sudo → Sudo and Sudo Caching
    "DOCKER-015": ["T1552.001"],  # Secret in ARG (image history)
    "DOCKER-021": ["T1222.002"],  # COPY --chmod=777
    "DOCKER-022": ["T1105"],  # ADD <url> → Ingress Tool Transfer
    "DOCKER-026": ["T1552.001", "T1552.004"],  # Credential / private key copied into image
    # ── Docker Compose ──────────────────────────────────────────────────────
    "COMPOSE-001": ["T1611"],  # privileged
    "COMPOSE-002": ["T1611", "T1610"],  # docker.sock → Escape to Host + Deploy Container
    "COMPOSE-003": ["T1611"],  # host network
    "COMPOSE-004": ["T1611"],  # host PID
    "COMPOSE-005": ["T1611"],  # escape capabilities
    "COMPOSE-006": ["T1552.001"],  # literal secret in environment
    "COMPOSE-007": ["T1611"],  # seccomp/AppArmor/SELinux disabled
    "COMPOSE-008": ["T1611"],  # host IPC/UTS/user namespace
    "COMPOSE-009": ["T1611", "T1552.001"],  # sensitive host path mounted
    "COMPOSE-010": ["T1611"],  # user: root
    "COMPOSE-011": ["T1548.001"],  # setuid escalation allowed → Setuid and Setgid
    # ── Docker daemon ───────────────────────────────────────────────────────
    "DOCKERD-001": ["T1133", "T1610"],  # Unauthenticated TCP API → External Remote Services + Deploy Container
    "DOCKERD-002": ["T1557"],  # Insecure registry → Adversary-in-the-Middle
    "DOCKERD-004": ["T1611"],  # No userns remap → container root is host root
    "DOCKERD-006": ["T1548.001"],  # setuid escalation allowed by default
    # ── Kubernetes ──────────────────────────────────────────────────────────
    "K8S-001": ["T1611"],  # Container running as root
    "K8S-002": ["T1611"],  # Privileged container
    "K8S-003": ["T1611"],  # Host PID namespace
    "K8S-004": ["T1611"],  # Host network namespace
    "K8S-005": ["T1610"],  # No resource limits → Deploy Container (DoS)
    "K8S-006": ["T1552.001"],  # Secrets in env vars
    "K8S-007": ["T1190"],  # Service type LoadBalancer without annotation
    "K8S-008": ["T1525"],  # Image not pinned to digest
    "K8S-009": ["T1562.001"],  # No readiness probe
    "K8S-010": ["T1562.001"],  # No liveness probe
    "K8S-011": ["T1078"],  # Default service account
    "K8S-012": ["T1611"],  # Writable root filesystem
    "K8S-013": ["T1611"],  # Capabilities not dropped
    "K8S-014": ["T1611"],  # allowPrivilegeEscalation true
    "K8S-015": ["T1190"],  # No network policy
    # ── CloudFormation ──────────────────────────────────────────────────────
    "CFN-001": ["T1530"],  # S3 without encryption
    "CFN-002": ["T1190", "T1530"],  # S3 public access
    "CFN-003": ["T1190"],  # SG open to world
    "CFN-004": ["T1078", "T1098"],  # IAM wildcards
    "CFN-005": ["T1530"],  # RDS without encryption
    "CFN-006": ["T1562.008"],  # CloudTrail disabled
    "CFN-007": ["T1552.004"],  # Hardcoded secrets
    "CFN-008": ["T1530"],  # EBS without encryption
    "CFN-009": ["T1562.008"],  # VPC no flow logs
    "CFN-010": ["T1552.005"],  # EC2 no IMDSv2
    # ── Helm ────────────────────────────────────────────────────────────────
    "HELM-001": ["T1611"],  # Container as root
    "HELM-002": ["T1611"],  # Privileged mode
    "HELM-003": ["T1525"],  # Image not pinned
    "HELM-004": ["T1610"],  # No resource limits
    "HELM-005": ["T1552.001"],  # Secrets in values
    "HELM-006": ["T1562.001"],  # No health checks
    "HELM-007": ["T1190"],  # Service exposed without policy
    # ── Snowflake DCM ───────────────────────────────────────────────────────
    "DCM-001": ["T1098", "T1078.004"],  # MANAGE GRANTS → Account Manipulation + Cloud Accounts
    "DCM-002": ["T1190"],  # NETWORK POLICY 0.0.0.0/0 → Exploit Public-Facing Application
    "DCM-003": ["T1098", "T1078"],  # GRANT ALL → Account Manipulation + Valid Accounts
    "DCM-004": ["T1496"],  # TASK without timeout → Resource Hijacking (unbounded credit burn)
    "DCM-005": ["T1190", "T1133"],  # SERVICE without policy → Public App + External Remote Services
    "DCM-006": ["T1078.004", "T1098"],  # GRANT ACCOUNTADMIN/SECURITYADMIN → Cloud Accounts + Account Manip.
    "DCM-007": ["T1078", "T1530"],  # USAGE on DATABASE → Valid Accounts + Data from Cloud Storage
    "DCM-008": ["T1078", "T1530"],  # Privilege to PUBLIC → Valid Accounts + Data from Cloud Storage
}


def get_attack_techniques(rule_id: str) -> list[str]:
    """Return MITRE ATT&CK technique IDs for a given IaC rule."""
    return IAC_ATTACK_MAP.get(rule_id, [])
