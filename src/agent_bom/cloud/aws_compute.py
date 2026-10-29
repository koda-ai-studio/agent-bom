"""Read-only AWS compute and hosted-model inventory collectors."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.normalization import (
    build_cloud_origin,
    build_cloud_principal,
    build_cloud_timestamps,
    build_package_purl,
    parse_container_image_package,
)
from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType


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
                    agent = _sagemaker_endpoint_agent(ep_desc, ep_name, model_name, image, execution_role, region, account_id)
                    agents.append(agent)

        except Exception as exc:
            warnings.append(f"Could not describe SageMaker endpoint {ep_name}: {exc}")

    return agents, warnings


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
                    agent = _ec2_instance_agent(instance, region, account_id)
                    agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not describe EC2 instances: {exc}")

    return agents, warnings


def _sagemaker_endpoint_agent(
    ep_desc: dict,
    ep_name: str,
    model_name: str,
    image: str,
    execution_role: str,
    region: str,
    account_id: str | None,
) -> Agent:
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
    return agent


def _ec2_instance_agent(instance: dict, region: str, account_id: str | None) -> Agent:
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
    return agent
