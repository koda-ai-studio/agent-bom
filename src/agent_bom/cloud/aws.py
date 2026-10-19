"""AWS cloud discovery — Bedrock agents, Lambda action groups, ECS tasks, SageMaker endpoints.

Requires ``boto3``.  Install with::

    pip install 'agent-bom[aws]'

Authentication uses the standard boto3 credential chain (env vars, ~/.aws/credentials,
IAM role, SSO).  Only *read* permissions are needed — no write APIs are ever called.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

from agent_bom.cloud.aws_iam import (
    _AWS_MANAGED_PRIVILEGE as _AWS_MANAGED_PRIVILEGE,
)
from agent_bom.cloud.aws_iam import (
    _WRITE_VERBS as _WRITE_VERBS,
)
from agent_bom.cloud.aws_iam import (
    _account_id_from_arn as _account_id_from_arn,
)
from agent_bom.cloud.aws_iam import (
    _classify_policy_actions as _classify_policy_actions,
)
from agent_bom.cloud.aws_iam import (
    _enrich_agents_with_iam as _enrich_agents_with_iam,
)
from agent_bom.cloud.aws_iam import (
    _extract_trust_principals as _extract_trust_principals,
)
from agent_bom.cloud.aws_iam import (
    _policy_actions_from_document as _policy_actions_from_document,
)
from agent_bom.cloud.aws_iam import (
    _policy_privilege as _policy_privilege,
)
from agent_bom.cloud.aws_iam import (
    _principal_name_from_id as _principal_name_from_id,
)
from agent_bom.cloud.aws_iam import (
    _principal_type_from_aws_principal as _principal_type_from_aws_principal,
)
from agent_bom.cloud.aws_iam import (
    _principal_values as _principal_values,
)
from agent_bom.cloud.aws_iam import (
    _role_name_from_arn as _role_name_from_arn,
)
from agent_bom.cloud.aws_lambda_packages import (
    _dedupe_packages as _dedupe_packages,
)
from agent_bom.cloud.aws_lambda_packages import (
    _extract_lambda_packages as _extract_lambda_packages,
)
from agent_bom.cloud.aws_lambda_packages import (
    _packages_from_layer as _packages_from_layer,
)
from agent_bom.cloud.aws_lambda_packages import (
    _parse_node_packages_from_zip as _parse_node_packages_from_zip,
)
from agent_bom.cloud.aws_lambda_packages import (
    _parse_python_packages_from_zip as _parse_python_packages_from_zip,
)
from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, ServerSurface, TransportType
from agent_bom.security import sanitize_text

from .aws_workloads import build_aws_workload_metadata
from .base import CloudDiscoveryError
from .normalization import (
    build_cloud_origin,
    build_cloud_principal,
    build_cloud_state,
    build_cloud_timestamps,
    build_package_purl,
    normalize_cloud_lifecycle_state,
    parse_container_image_package,
)

logger = logging.getLogger(__name__)

_MAX_AWS_DISCOVERY_WORKERS = 4

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_AwsJobResult = tuple[list[Agent], list[str], list[dict[str, str] | str]]
_AwsDiscoveryJob = Callable[[], _AwsJobResult]
_AwsCollector = Callable[..., tuple[list[Agent], list[str]]]
_SessionFactory = Callable[[], Any]

_AWS_ACCESS_DENIED_WARNINGS = {
    "bedrock": "Access denied for bedrock-agent:ListAgents. Attach the BedrockAgentReadOnly or AmazonBedrockReadOnly policy.",
    "ecs": "Access denied for ECS APIs. Attach AmazonECSReadOnlyAccess policy.",
    "sagemaker": "Access denied for SageMaker APIs. Attach AmazonSageMakerReadOnly policy.",
    "lambda": "Access denied for Lambda APIs. Attach AWSLambda_ReadOnlyAccess policy.",
    "eks": "Access denied for EKS APIs. Attach AmazonEKSReadOnlyAccess policy.",
    "step-functions": "Access denied for Step Functions APIs. Attach AWSStepFunctionsReadOnlyAccess policy.",
    "ec2": "Access denied for EC2 APIs. Attach AmazonEC2ReadOnlyAccess policy.",
}
_AWS_API_ERROR_LABELS = {
    "bedrock": "AWS Bedrock API error",
    "ecs": "AWS ECS API error",
    "sagemaker": "AWS SageMaker API error",
    "lambda": "AWS Lambda API error",
    "eks": "AWS EKS API error",
    "step-functions": "AWS Step Functions API error",
    "ec2": "AWS EC2 API error",
}


def discover(
    region: str | None = None,
    profile: str | None = None,
    include_ecs: bool = True,
    include_sagemaker: bool = False,
    include_lambda: bool = True,
    include_eks: bool = False,
    include_step_functions: bool = False,
    include_ec2: bool = False,
    include_iam: bool = False,
    ec2_tag_filter: dict[str, str] | None = None,
    tag_filter: dict[str, str] | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from AWS Bedrock, Lambda, ECS, EKS, Step Functions, and more.

    Returns:
        (agents, warnings) — agents found and non-fatal warning strings.

    Raises:
        CloudDiscoveryError: if ``boto3`` is not installed.
    """
    try:
        import boto3  # noqa: F811
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        raise CloudDiscoveryError("boto3 is required for AWS discovery. Install with: pip install 'agent-bom[aws]'")

    agents: list[Agent] = []
    warnings: list[str] = []
    ecs_image_refs: list[dict[str, str] | str] = []

    session_kwargs: dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region
    if profile:
        session_kwargs["profile_name"] = profile

    session = boto3.Session(**session_kwargs)
    resolved_region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    account_id = _resolve_account_id(session)

    def _new_discovery_session() -> Any:
        return boto3.Session(**session_kwargs)

    flags = {
        "include_ecs": include_ecs,
        "include_sagemaker": include_sagemaker,
        "include_lambda": include_lambda,
        "include_eks": include_eks,
        "include_step_functions": include_step_functions,
        "include_ec2": include_ec2,
    }
    discovery_jobs = _build_aws_discovery_jobs(_new_discovery_session, resolved_region, account_id, ec2_tag_filter=ec2_tag_filter, **flags)
    if not _collect_aws_discovery_jobs(
        discovery_jobs, agents, warnings, ecs_image_refs, client_error=ClientError, no_credentials_error=NoCredentialsError
    ):
        return agents, warnings

    if include_iam:
        _enrich_agents_with_iam(_new_discovery_session(), agents, account_id=account_id, warnings=warnings)

    agents.extend(_ecs_image_agents(ecs_image_refs, region=resolved_region, account_id=account_id))

    permissions_used = _aws_permissions_for_jobs(include_iam=include_iam, **flags)
    _attach_aws_discovery_envelope(
        agents, account_id=account_id, region=resolved_region, tag_filter=tag_filter, permissions_used=permissions_used
    )
    return agents, warnings


def _agents_job(discover_fn: _AwsCollector, new_session: _SessionFactory, region: str, *args: Any, account_id: str | None) -> _AwsJobResult:
    """Run a ``(session, region, *args, account_id=...)`` service collector."""
    service_agents, service_warnings = discover_fn(new_session(), region, *args, account_id=account_id)
    return service_agents, service_warnings, []


def _parent_warnings_job(discover_fn: _AwsCollector, new_session: _SessionFactory, region: str, *, account_id: str | None) -> _AwsJobResult:
    """Run a collector that also reports into a parent warning list (Lambda, Step Functions)."""
    parent_warnings: list[str] = []
    service_agents, service_warnings = discover_fn(new_session(), region, parent_warnings, account_id=account_id)
    return service_agents, [*parent_warnings, *service_warnings], []


def _ecs_job(new_session: _SessionFactory, region: str) -> _AwsJobResult:
    ecs_refs, ecs_warns = _discover_ecs_images(new_session(), region)
    return [], ecs_warns, list(ecs_refs)


def _build_aws_discovery_jobs(
    new_session: _SessionFactory,
    region: str,
    account_id: str | None,
    *,
    include_ecs: bool,
    include_sagemaker: bool,
    include_lambda: bool,
    include_eks: bool,
    include_step_functions: bool,
    include_ec2: bool,
    ec2_tag_filter: dict[str, str] | None,
) -> list[tuple[str, _AwsDiscoveryJob]]:
    """Return the ordered (service, job) list for every enabled AWS collector."""
    jobs: list[tuple[str, _AwsDiscoveryJob]] = [
        ("bedrock", partial(_agents_job, _discover_bedrock, new_session, region, account_id=account_id))
    ]
    if include_ecs:
        jobs.append(("ecs", partial(_ecs_job, new_session, region)))
    if include_sagemaker:
        jobs.append(("sagemaker", partial(_agents_job, _discover_sagemaker, new_session, region, account_id=account_id)))
    if include_lambda:
        jobs.append(("lambda", partial(_parent_warnings_job, _discover_lambda_functions, new_session, region, account_id=account_id)))
    if include_eks:
        jobs.append(("eks", partial(_agents_job, _discover_eks_images, new_session, region, account_id=account_id)))
    if include_step_functions:
        jobs.append(("step-functions", partial(_parent_warnings_job, _discover_step_functions, new_session, region, account_id=account_id)))
    if include_ec2:
        ec2_job = partial(_agents_job, _discover_ec2_instances, new_session, region, ec2_tag_filter or {}, account_id=account_id)
        jobs.append(("ec2", ec2_job))
    return jobs


def _collect_aws_discovery_jobs(
    discovery_jobs: list[tuple[str, _AwsDiscoveryJob]],
    agents: list[Agent],
    warnings: list[str],
    ecs_image_refs: list[dict[str, str] | str],
    *,
    client_error: Any,
    no_credentials_error: Any,
) -> bool:
    """Run every job concurrently and merge results in job order.

    Returns ``False`` when Bedrock reports missing credentials, in which case
    the caller must stop and return what it has.
    """
    if not discovery_jobs:
        return True
    with ThreadPoolExecutor(max_workers=min(_MAX_AWS_DISCOVERY_WORKERS, len(discovery_jobs))) as executor:
        futures_by_service = {service: executor.submit(job) for service, job in discovery_jobs}

        for service, _job in discovery_jobs:
            future = futures_by_service[service]
            try:
                service_agents, service_warnings, service_ecs_refs = future.result()
            except no_credentials_error:
                if service == "bedrock":
                    warnings.append("AWS credentials not found. Configure via env vars, ~/.aws/credentials, IAM role, or SSO.")
                    return False
                raise
            except client_error as exc:
                code = exc.response["Error"]["Code"]
                if code in ("AccessDeniedException", "UnauthorizedAccess"):
                    warnings.append(_AWS_ACCESS_DENIED_WARNINGS[service])
                else:
                    warnings.append(f"{_AWS_API_ERROR_LABELS[service]}: {exc}")
                continue

            agents.extend(service_agents)
            warnings.extend(service_warnings)
            ecs_image_refs.extend(service_ecs_refs)
    return True


def _ecs_image_agents(ecs_image_refs: list[dict[str, str] | str], *, region: str, account_id: str | None) -> list[Agent]:
    """Turn collected ECS container image references into image agents."""
    ecs_agents: list[Agent] = []
    for ecs_ref in ecs_image_refs:
        ref = ecs_ref if isinstance(ecs_ref, dict) else {"image": ecs_ref}
        img_ref = ref.get("image", "")
        cluster_arn = ref.get("cluster_arn", "")
        task_arn = ref.get("task_arn", "")
        container_name = ref.get("container_name", img_ref)
        if not img_ref:
            continue
        ecs_agent = Agent(
            name=f"ecs-image:{img_ref}",
            agent_type=AgentType.CUSTOM,
            config_path=task_arn or f"ecs://{img_ref}",
            source="aws-ecs",
            mcp_servers=[
                MCPServer(
                    name=img_ref,
                    command="docker",
                    args=["run", img_ref],
                    transport=TransportType.STDIO,
                    packages=[
                        Package(
                            name=parts[0],
                            version=parts[1],
                            ecosystem="container-image",
                            purl=build_package_purl(ecosystem="container-image", name=parts[0], version=parts[1]),
                        )
                        for parts in [parse_container_image_package(img_ref)]
                        if parts
                    ],
                )
            ],
            metadata={
                "cloud_origin": build_cloud_origin(
                    provider="aws",
                    service="ecs",
                    resource_type="container-image",
                    resource_id=f"{task_arn}/{container_name}" if task_arn else img_ref,
                    resource_name=container_name or img_ref.split("/")[-1],
                    location=region,
                    account_id=account_id,
                    raw_identity={
                        "cluster_arn": cluster_arn,
                        "task_arn": task_arn,
                        "container_name": container_name,
                        "image": img_ref,
                    },
                )
            },
        )
        ecs_agents.append(ecs_agent)
    return ecs_agents


def _attach_aws_discovery_envelope(
    agents: list[Agent],
    *,
    account_id: str | None,
    region: str,
    tag_filter: dict[str, str] | None,
    permissions_used: tuple[str, ...],
) -> None:
    """Stamp the per-run discovery envelope (#2083): the modes / scope / IAM permissions
    actually exercised, plus the redaction posture. The central sanitizer in
    `agent_bom.security` scrubs values before storage (`central_sanitizer_applied`)."""
    discovery_scope: list[str] = []
    if account_id:
        discovery_scope.append(f"aws:account/{account_id}")
    if region:
        discovery_scope.append(f"aws:region/{region}")
    if tag_filter:
        discovery_scope.extend(f"aws:tag/{k}={v}" for k, v in sorted(tag_filter.items()))

    envelope_payload = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=tuple(discovery_scope),
        permissions_used=permissions_used,
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    ).to_dict()
    for agent in agents:
        if agent.discovery_envelope is None:
            agent.discovery_envelope = envelope_payload


# IAM permissions exercised by AWS provider helpers, by job. Each entry is
# the read-only API call list the corresponding `_discover_*` function
# actually issues. Kept here so the per-run envelope `permissions_used`
# field stays honest -- producers control the catalog, not external docs.
_AWS_BEDROCK_PERMISSIONS: tuple[str, ...] = (
    "bedrock-agent:ListAgents",
    "bedrock-agent:GetAgent",
    "bedrock-agent:ListAgentActionGroups",
    "bedrock-agent:GetAgentActionGroup",
    "bedrock-agent:ListAgentKnowledgeBases",
)
_AWS_ECS_PERMISSIONS: tuple[str, ...] = (
    "ecs:ListClusters",
    "ecs:ListTasks",
    "ecs:DescribeTasks",
    "ecs:DescribeTaskDefinition",
)
_AWS_SAGEMAKER_PERMISSIONS: tuple[str, ...] = (
    "sagemaker:ListEndpoints",
    "sagemaker:DescribeEndpoint",
    "sagemaker:DescribeEndpointConfig",
    "sagemaker:DescribeModel",
)
_AWS_LAMBDA_PERMISSIONS: tuple[str, ...] = (
    "lambda:ListFunctions",
    "lambda:GetFunction",
)
_AWS_EKS_PERMISSIONS: tuple[str, ...] = (
    "eks:ListClusters",
    "eks:DescribeCluster",
)
_AWS_STEP_FUNCTIONS_PERMISSIONS: tuple[str, ...] = (
    "states:ListStateMachines",
    "states:DescribeStateMachine",
)
_AWS_EC2_PERMISSIONS: tuple[str, ...] = ("ec2:DescribeInstances",)
_AWS_IAM_PERMISSIONS: tuple[str, ...] = (
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
)
_AWS_BASELINE_PERMISSIONS: tuple[str, ...] = ("sts:GetCallerIdentity",)


def _aws_permissions_for_jobs(
    *,
    include_ecs: bool,
    include_sagemaker: bool,
    include_lambda: bool,
    include_eks: bool,
    include_step_functions: bool,
    include_ec2: bool,
    include_iam: bool = False,
) -> tuple[str, ...]:
    """Return the IAM action list this run is allowed to exercise.

    Bedrock + the baseline `sts:GetCallerIdentity` are always in scope
    because `discover()` always tries to resolve the account and list agents.
    Other services are gated on the include_* flags.
    """
    perms: list[str] = list(_AWS_BASELINE_PERMISSIONS) + list(_AWS_BEDROCK_PERMISSIONS)
    if include_ecs:
        perms.extend(_AWS_ECS_PERMISSIONS)
    if include_sagemaker:
        perms.extend(_AWS_SAGEMAKER_PERMISSIONS)
    if include_lambda:
        perms.extend(_AWS_LAMBDA_PERMISSIONS)
    if include_eks:
        perms.extend(_AWS_EKS_PERMISSIONS)
    if include_step_functions:
        perms.extend(_AWS_STEP_FUNCTIONS_PERMISSIONS)
    if include_ec2:
        perms.extend(_AWS_EC2_PERMISSIONS)
    if include_iam:
        perms.extend(_AWS_IAM_PERMISSIONS)
    return tuple(sorted(set(perms)))


def _resolve_account_id(session: Any) -> str | None:
    """Resolve the AWS account once for normalized origin scope.

    STS can be unavailable or explicitly denied in least-privilege audit roles;
    inventory discovery should continue and simply omit account scope.
    """
    try:
        identity = session.client("sts").get_caller_identity()
    except Exception as exc:
        logger.debug("Could not resolve AWS account ID via STS: %s", sanitize_text(exc))
        return None
    account_id = str(identity.get("Account", "")).strip()
    return account_id or None


# ---------------------------------------------------------------------------
# Bedrock discovery
# ---------------------------------------------------------------------------


def _discover_bedrock(session: Any, region: str, *, account_id: str | None = None) -> tuple[list[Agent], list[str]]:
    """Discover Bedrock agents and their action groups."""
    client = session.client("bedrock-agent", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    # Paginate through all agents
    paginator = client.get_paginator("list_agents")
    for page in paginator.paginate():
        for summary in page.get("agentSummaries", []):
            agent_id = summary["agentId"]
            agent_name = summary.get("agentName", agent_id)
            agent_status = summary.get("agentStatus", "UNKNOWN")
            lifecycle_state = normalize_cloud_lifecycle_state(
                provider="aws",
                service="bedrock",
                resource_type="agent",
                raw_state=agent_status,
            )

            try:
                detail = client.get_agent(agentId=agent_id)["agent"]
            except Exception as exc:
                warnings.append(f"Could not get details for Bedrock agent {agent_id}: {exc}")
                continue

            agent_arn = detail.get("agentArn") or f"arn:aws:bedrock:{region}:{account_id or ''}:agent/{agent_id}"
            foundation_model = detail.get("foundationModel", "unknown")
            runtime_role_arn = detail.get("agentResourceRoleArn", "")

            # Discover action groups → Lambda functions
            mcp_servers = _get_action_group_servers(client, session, agent_id, region, warnings)

            agent = Agent(
                name=f"bedrock:{agent_name}",
                agent_type=AgentType.CUSTOM,
                config_path=agent_arn,
                source="aws-bedrock",
                version=foundation_model,
                mcp_servers=mcp_servers,
                metadata={
                    "cloud_origin": build_cloud_origin(
                        provider="aws",
                        service="bedrock",
                        resource_type="agent",
                        resource_id=agent_arn,
                        resource_name=agent_name,
                        location=region,
                        account_id=account_id,
                        raw_identity={
                            "agentId": agent_id,
                            "agentArn": agent_arn,
                            "agentName": agent_name,
                        },
                    ),
                },
            )
            if lifecycle_state:
                agent.metadata["cloud_state"] = build_cloud_state(
                    provider="aws",
                    service="bedrock",
                    resource_type="agent",
                    lifecycle_state=lifecycle_state,
                    raw_state=agent_status,
                    state_source="agentStatus",
                )
            cloud_principal = build_cloud_principal(
                provider="aws",
                service="bedrock",
                resource_type="agent",
                principal_type="iam-role",
                principal_id=runtime_role_arn or None,
                source_field="agentResourceRoleArn",
                raw_identity={"role_arn": runtime_role_arn},
            )
            if cloud_principal:
                agent.metadata["cloud_principal"] = cloud_principal
            agents.append(agent)

    return agents, warnings


def _get_action_group_servers(
    bedrock_client: Any,
    session: Any,
    agent_id: str,
    region: str,
    warnings: list[str],
) -> list[MCPServer]:
    """Convert Bedrock agent action groups into MCPServer objects."""
    servers: list[MCPServer] = []

    try:
        paginator = bedrock_client.get_paginator("list_agent_action_groups")
        for page in paginator.paginate(agentId=agent_id, agentVersion="DRAFT"):
            for ag in page.get("actionGroupSummaries", []):
                ag_name = ag.get("actionGroupName", "unknown")
                ag_id = ag.get("actionGroupId", "")

                try:
                    detail = bedrock_client.get_agent_action_group(
                        agentId=agent_id,
                        agentVersion="DRAFT",
                        actionGroupId=ag_id,
                    )["agentActionGroup"]
                except Exception:
                    continue

                executor = detail.get("actionGroupExecutor", {})
                lambda_arn = executor.get("lambda")

                # Extract tools from the action group API schema
                tools = _extract_tools_from_schema(detail)

                # Extract packages from Lambda layers if we have a Lambda ARN
                packages: list[Package] = []
                if lambda_arn:
                    packages = _extract_lambda_packages(session, lambda_arn, region, warnings)

                server = MCPServer(
                    name=f"action-group:{ag_name}",
                    command="lambda" if lambda_arn else "",
                    args=[lambda_arn] if lambda_arn else [],
                    transport=TransportType.STREAMABLE_HTTP,
                    env={"AWS_REGION": region},
                    tools=tools,
                    packages=packages,
                )
                servers.append(server)

    except Exception as exc:
        warnings.append(f"Could not list action groups for agent {agent_id}: {exc}")

    return servers


def _extract_tools_from_schema(action_group_detail: dict) -> list[MCPTool]:
    """Extract tool definitions from an action group's API schema."""
    tools: list[MCPTool] = []

    api_schema = action_group_detail.get("apiSchema", {})
    # The schema can be inline JSON or an S3 reference
    payload = api_schema.get("payload", "")
    if not payload:
        # Function schema — simpler format
        func_schema = action_group_detail.get("functionSchema", {})
        for func in func_schema.get("functions", []):
            tools.append(
                MCPTool(
                    name=func.get("name", "unknown"),
                    description=func.get("description", ""),
                )
            )
        return tools

    # Parse OpenAPI spec
    try:
        spec = json.loads(payload) if isinstance(payload, str) else payload
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, op in methods.items():
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    op_id = op.get("operationId", f"{method.upper()} {path}")
                    tools.append(
                        MCPTool(
                            name=op_id,
                            description=op.get("summary", op.get("description", "")),
                        )
                    )
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Failed to parse OpenAPI spec for Lambda tool extraction: %s", sanitize_text(exc))

    return tools


# ---------------------------------------------------------------------------
# ECS discovery
# ---------------------------------------------------------------------------


def _discover_ecs_images(session: Any, region: str) -> tuple[list[dict[str, str]], list[str]]:
    """Discover container image refs from running ECS tasks."""
    ecs = session.client("ecs", region_name=region)
    image_refs: list[dict[str, str]] = []
    warnings: list[str] = []
    seen: set[str] = set()

    try:
        cluster_arns: list[str] = []
        paginator = ecs.get_paginator("list_clusters")
        for page in paginator.paginate():
            cluster_arns.extend(page.get("clusterArns", []))
    except Exception as exc:
        return [], [f"Could not list ECS clusters: {exc}"]

    for cluster_arn in cluster_arns:
        try:
            task_arns: list[str] = []
            task_paginator = ecs.get_paginator("list_tasks")
            for page in task_paginator.paginate(cluster=cluster_arn, desiredStatus="RUNNING"):
                task_arns.extend(page.get("taskArns", []))
            if not task_arns:
                continue

            # DescribeTasks accepts max 100 tasks per call
            for i in range(0, len(task_arns), 100):
                batch = task_arns[i : i + 100]
                tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=batch).get("tasks", [])
                for task in tasks:
                    task_arn = task.get("taskArn", "")
                    for container in task.get("containers", []):
                        image = container.get("image", "")
                        container_name = container.get("name", "") or image
                        if image and image not in seen:
                            seen.add(image)
                            image_refs.append(
                                {
                                    "cluster_arn": cluster_arn,
                                    "task_arn": task_arn,
                                    "container_name": container_name,
                                    "image": image,
                                }
                            )
        except Exception as exc:
            warnings.append(f"Could not list tasks in ECS cluster {cluster_arn}: {exc}")

    return image_refs, warnings


# ---------------------------------------------------------------------------
# SageMaker discovery
# ---------------------------------------------------------------------------


def _discover_sagemaker(session: Any, region: str, *, account_id: str | None = None) -> tuple[list[Agent], list[str]]:
    """Discover SageMaker endpoints and their container images."""
    sm = session.client("sagemaker", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        endpoints: list[dict] = []
        paginator = sm.get_paginator("list_endpoints")
        for page in paginator.paginate(StatusEquals="InService"):
            endpoints.extend(page.get("Endpoints", []))
    except Exception as exc:
        return [], [f"Could not list SageMaker endpoints: {exc}"]

    for ep in endpoints:
        ep_name = ep["EndpointName"]
        try:
            ep_desc = sm.describe_endpoint(EndpointName=ep_name)
            config_name = ep_desc.get("EndpointConfigName", "")
            if not config_name:
                continue

            config_desc = sm.describe_endpoint_config(EndpointConfigName=config_name)
            for variant in config_desc.get("ProductionVariants", []):
                model_name = variant.get("ModelName", "")
                if not model_name:
                    continue

                model_desc = sm.describe_model(ModelName=model_name)
                container = model_desc.get("PrimaryContainer", {})
                image = container.get("Image", "")
                execution_role = model_desc.get("ExecutionRoleArn", "")

                if image:
                    image_parts = parse_container_image_package(image)
                    server = MCPServer(
                        name=f"sagemaker-model:{model_name}",
                        command="docker",
                        args=["run", image],
                        transport=TransportType.STDIO,
                        env={"AWS_REGION": region},
                        packages=[
                            Package(
                                name=image_parts[0],
                                version=image_parts[1],
                                ecosystem="container-image",
                                purl=build_package_purl(ecosystem="container-image", name=image_parts[0], version=image_parts[1]),
                            )
                        ]
                        if image_parts
                        else [],
                    )
                    agent = Agent(
                        name=f"sagemaker:{ep_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=ep_desc.get("EndpointArn", f"sagemaker://{ep_name}"),
                        source="aws-sagemaker",
                        mcp_servers=[server],
                        metadata={
                            "cloud_origin": build_cloud_origin(
                                provider="aws",
                                service="sagemaker",
                                resource_type="endpoint",
                                resource_id=ep_desc.get("EndpointArn", ep_name),
                                resource_name=ep_name,
                                location=region,
                                account_id=account_id,
                                raw_identity={"endpoint": ep_name, "model": model_name, "image": image},
                            )
                        },
                    )
                    cloud_timestamps = build_cloud_timestamps(
                        provider="aws",
                        service="sagemaker",
                        resource_type="endpoint",
                        created_at=ep_desc.get("CreationTime"),
                        updated_at=ep_desc.get("LastModifiedTime"),
                        created_source="CreationTime",
                        updated_source="LastModifiedTime",
                    )
                    if cloud_timestamps:
                        agent.metadata["cloud_timestamps"] = cloud_timestamps
                    cloud_principal = build_cloud_principal(
                        provider="aws",
                        service="sagemaker",
                        resource_type="endpoint",
                        principal_type="iam-role",
                        principal_id=execution_role or None,
                        source_field="Model.ExecutionRoleArn",
                        raw_identity={"execution_role_arn": execution_role},
                    )
                    if cloud_principal:
                        agent.metadata["cloud_principal"] = cloud_principal
                    agents.append(agent)

        except Exception as exc:
            warnings.append(f"Could not describe SageMaker endpoint {ep_name}: {exc}")

    return agents, warnings


# ---------------------------------------------------------------------------
# Lambda direct discovery
# ---------------------------------------------------------------------------

_AI_RUNTIMES = {
    "python3.9",
    "python3.10",
    "python3.11",
    "python3.12",
    "python3.13",
    "nodejs18.x",
    "nodejs20.x",
    "nodejs22.x",
}


def _discover_lambda_functions(
    session: Any,
    region: str,
    parent_warnings: list[str],
    *,
    account_id: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover standalone Lambda functions (not just Bedrock action group Lambdas).

    Filters by runtime to focus on AI-relevant functions (Python, Node.js).
    Reuses ``_extract_lambda_packages()`` for layer scanning.
    """
    lambda_client = session.client("lambda", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for func in page.get("Functions", []):
            func_name = func.get("FunctionName", "unknown")
            func_arn = func.get("FunctionArn", "")
            runtime = func.get("Runtime", "")
            role_arn = func.get("Role", "")

            if runtime not in _AI_RUNTIMES:
                continue

            packages = _extract_lambda_packages(session, func_arn, region, parent_warnings)

            server = MCPServer(
                name=f"lambda:{func_name}",
                command="lambda",
                args=[func_arn],
                transport=TransportType.UNKNOWN,
                surface=ServerSurface.AI_INVENTORY,
                env={"AWS_REGION": region},
                packages=packages,
            )

            agent = Agent(
                name=f"lambda:{func_name}",
                agent_type=AgentType.CUSTOM,
                config_path=func_arn,
                source="aws-lambda",
                version=runtime,
                mcp_servers=[server],
                metadata=build_aws_workload_metadata(
                    service="lambda",
                    resource_type="function",
                    resource_id=func_arn,
                    resource_name=func_name,
                    region=region,
                    account_id=account_id,
                    role_arn=role_arn,
                    role_field="Role",
                    raw_identity={
                        "function_name": func_name,
                        "function_arn": func_arn,
                        "runtime": runtime,
                        "function_version": func.get("Version", ""),
                    },
                    updated_at=func.get("LastModified"),
                    updated_source="LastModified",
                ),
            )
            agents.append(agent)

    return agents, warnings


# ---------------------------------------------------------------------------
# EKS discovery
# ---------------------------------------------------------------------------


def _discover_eks_images(
    session: Any,
    region: str,
    *,
    account_id: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover EKS clusters and reuse k8s.discover_images() for pod scanning.

    Requires kubectl configured with access to the discovered clusters.
    """
    eks_client = session.client("eks", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        from agent_bom.k8s import K8sDiscoveryError, discover_images
    except ImportError:
        warnings.append("k8s module not available for EKS discovery.")
        return agents, warnings

    try:
        cluster_names: list[str] = []
        paginator = eks_client.get_paginator("list_clusters")
        for page in paginator.paginate():
            cluster_names.extend(page.get("clusters", []))
    except Exception as exc:
        return [], [f"Could not list EKS clusters: {exc}"]

    for cluster_name in cluster_names:
        try:
            image_records = discover_images(all_namespaces=True, context=cluster_name)
            for image_ref, pod_name, container_name in image_records:
                image_parts = parse_container_image_package(image_ref)
                server = MCPServer(
                    name=image_ref,
                    command="docker",
                    args=["run", image_ref],
                    transport=TransportType.STDIO,
                    packages=[
                        Package(
                            name=image_parts[0],
                            version=image_parts[1],
                            ecosystem="container-image",
                            purl=build_package_purl(ecosystem="container-image", name=image_parts[0], version=image_parts[1]),
                        )
                    ]
                    if image_parts
                    else [],
                )
                agent = Agent(
                    name=f"eks:{cluster_name}/{pod_name}/{container_name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"eks://{cluster_name}/{pod_name}",
                    source="aws-eks",
                    mcp_servers=[server],
                    metadata={
                        "cloud_origin": build_cloud_origin(
                            provider="aws",
                            service="eks",
                            resource_type="pod-image",
                            resource_id=f"{cluster_name}/{pod_name}/{container_name}",
                            resource_name=pod_name,
                            location=region,
                            account_id=account_id,
                            raw_identity={
                                "cluster": cluster_name,
                                "pod": pod_name,
                                "container": container_name,
                                "image": image_ref,
                            },
                        )
                    },
                )
                agents.append(agent)

        except K8sDiscoveryError as exc:
            warnings.append(
                f"Could not discover images in EKS cluster '{cluster_name}': {exc}. "
                f"Ensure kubectl context is configured (aws eks update-kubeconfig --name {cluster_name})"
            )

    return agents, warnings


# ---------------------------------------------------------------------------
# Step Functions discovery
# ---------------------------------------------------------------------------


def _discover_step_functions(
    session: Any,
    region: str,
    parent_warnings: list[str],
    *,
    account_id: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover Step Functions state machines and extract referenced service ARNs.

    Parses the state machine definition JSON to find Task states with Lambda,
    SageMaker, and Bedrock resource ARNs.
    """
    sfn_client = session.client("stepfunctions", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    paginator = sfn_client.get_paginator("list_state_machines")
    for page in paginator.paginate():
        for sm in page.get("stateMachines", []):
            sm_arn = sm.get("stateMachineArn", "")
            sm_name = sm.get("name", "unknown")

            try:
                detail = sfn_client.describe_state_machine(stateMachineArn=sm_arn)
                definition_str = detail.get("definition", "{}")
                definition = json.loads(definition_str)
                role_arn = detail.get("roleArn", "")
            except Exception as exc:
                warnings.append(f"Could not describe Step Function {sm_name}: {exc}")
                continue

            resource_arns = _extract_sfn_task_resources(definition)
            if not resource_arns:
                continue

            servers: list[MCPServer] = []
            tools: list[MCPTool] = []

            for arn in resource_arns:
                if ":lambda:" in arn:
                    packages = _extract_lambda_packages(session, arn, region, parent_warnings)
                    func_name = arn.split(":function:", 1)[-1]
                    servers.append(
                        MCPServer(
                            name=f"sfn-lambda:{func_name}",
                            command="lambda",
                            args=[arn],
                            transport=TransportType.UNKNOWN,
                            surface=ServerSurface.AI_INVENTORY,
                            connection_metadata={"relationship_basis": "configured_workflow_target", "execution_proven": False},
                            packages=packages,
                        )
                    )
                else:
                    service = arn.split(":")[2] if len(arn.split(":")) > 2 else "aws"
                    tools.append(
                        MCPTool(
                            name=f"{service}:{arn.split(':')[-1]}",
                            description=f"Step Functions task resource: {arn}",
                        )
                    )

            if not servers:
                servers = [
                    MCPServer(
                        name=f"sfn-orchestration:{sm_name}",
                        surface=ServerSurface.AI_INVENTORY,
                        transport=TransportType.UNKNOWN,
                        tools=tools,
                    )
                ]

            agent = Agent(
                name=f"step-functions:{sm_name}",
                agent_type=AgentType.CUSTOM,
                config_path=sm_arn,
                source="aws-step-functions",
                mcp_servers=servers,
                metadata=build_aws_workload_metadata(
                    service="step-functions",
                    resource_type="state-machine",
                    resource_id=sm_arn,
                    resource_name=sm_name,
                    region=region,
                    account_id=account_id,
                    role_arn=role_arn,
                    role_field="roleArn",
                    raw_identity={"state_machine_arn": sm_arn, "name": sm_name},
                    created_at=sm.get("creationDate") or detail.get("creationDate"),
                    created_source="creationDate",
                ),
            )
            agents.append(agent)

    return agents, warnings


def _extract_sfn_task_resources(definition: dict) -> list[str]:
    """Recursively extract Task.Resource ARNs from a Step Functions definition."""
    resources: list[str] = []

    def _walk_states(states: dict) -> None:
        for _state_name, state_def in states.items():
            state_type = state_def.get("Type", "")

            if state_type == "Task":
                resource = state_def.get("Resource", "")
                if isinstance(resource, str) and resource.startswith("arn:") and ":states:::" not in resource:
                    resources.append(resource)
                params = state_def.get("Parameters", {})
                fn_name = params.get("FunctionName", "")
                if isinstance(fn_name, str) and fn_name.startswith("arn:"):
                    resources.append(fn_name)

            elif state_type == "Parallel":
                for branch in state_def.get("Branches", []):
                    _walk_states(branch.get("States", {}))

            elif state_type == "Map":
                iterator = state_def.get("Iterator", state_def.get("ItemProcessor", {}))
                _walk_states(iterator.get("States", {}))

    _walk_states(definition.get("States", {}))
    return sorted(set(resources))


# ---------------------------------------------------------------------------
# EC2 discovery
# ---------------------------------------------------------------------------


def _aws_instance_network(instance: dict) -> dict[str, Any]:
    """Extract low-risk network placement (subnet/VPC/SG ids, IPs, AZ) from a
    describe_instances Instance. Identifiers only — no rules, no credentials."""
    sg_ids: list[str] = []
    for group in instance.get("SecurityGroups", []) or []:
        gid = group.get("GroupId") if isinstance(group, dict) else None
        if gid and gid not in sg_ids:
            sg_ids.append(gid)
    for nic in instance.get("NetworkInterfaces", []) or []:
        for group in (nic.get("Groups", []) if isinstance(nic, dict) else []) or []:
            gid = group.get("GroupId") if isinstance(group, dict) else None
            if gid and gid not in sg_ids:
                sg_ids.append(gid)
    placement_raw = instance.get("Placement")
    placement = placement_raw if isinstance(placement_raw, dict) else {}
    network = {
        "subnet_id": instance.get("SubnetId", ""),
        "vpc_id": instance.get("VpcId", ""),
        "public_ip": instance.get("PublicIpAddress", ""),
        "private_ip": instance.get("PrivateIpAddress", ""),
        "availability_zone": placement.get("AvailabilityZone", ""),
        "security_group_ids": sg_ids,
    }
    return {k: v for k, v in network.items() if v}


def _discover_ec2_instances(
    session: Any,
    region: str,
    tag_filter: dict[str, str],
    *,
    account_id: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover EC2 instances matching tag filters.

    Inventory-only: without SSH access we cannot extract packages,
    but we record the instance metadata for audit/compliance purposes.
    """
    ec2_client = session.client("ec2", region_name=region)
    agents: list[Agent] = []
    warnings: list[str] = []

    if not tag_filter:
        warnings.append(
            "EC2 discovery requires --aws-ec2-tag KEY=VALUE to filter instances. Scanning all instances is not supported for safety."
        )
        return agents, warnings

    filters: list[dict[str, Any]] = []
    for key, value in tag_filter.items():
        filters.append({"Name": f"tag:{key}", "Values": [value]})
    filters.append({"Name": "instance-state-name", "Values": ["running"]})

    try:
        paginator = ec2_client.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=filters):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "unknown")
                    instance_type = instance.get("InstanceType", "")
                    ami_id = instance.get("ImageId", "")
                    launch_time = instance.get("LaunchTime")

                    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                    name = tags.get("Name", instance_id)

                    server = MCPServer(
                        name=f"ec2:{instance_id}",
                        transport=TransportType.UNKNOWN,
                        env={"INSTANCE_TYPE": instance_type, "AMI_ID": ami_id},
                    )

                    agent = Agent(
                        name=f"ec2:{name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"arn:aws:ec2:{region}::instance/{instance_id}",
                        source="aws-ec2",
                        version=f"{instance_type} ({ami_id})",
                        mcp_servers=[server],
                        metadata={
                            "cloud_origin": build_cloud_origin(
                                provider="aws",
                                service="ec2",
                                resource_type="instance",
                                resource_id=instance_id,
                                resource_name=name,
                                location=region,
                                account_id=account_id,
                                raw_identity={"instance_id": instance_id, "instance_type": instance_type, "ami_id": ami_id},
                                network=_aws_instance_network(instance),
                            )
                        },
                    )
                    cloud_timestamps = build_cloud_timestamps(
                        provider="aws",
                        service="ec2",
                        resource_type="instance",
                        created_at=launch_time,
                        created_source="LaunchTime",
                    )
                    if cloud_timestamps:
                        agent.metadata["cloud_timestamps"] = cloud_timestamps
                    agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not describe EC2 instances: {exc}")

    return agents, warnings
