"""AWS internet-edge service discovery (load balancers, CloudFront, messaging, WAF, API Gateway)."""

from __future__ import annotations

from typing import Any

from ..normalization import sanitize_discovery_warning
from ._base import record_discovery_failure


def _discover_elb_targets(
    client: Any, lb_arn: str, *, warnings: list[str], missing: list[dict[str, str]] | None
) -> tuple[list[dict[str, Any]], bool]:
    """Read registered targets, preserving partial results and permission gaps."""
    targets: list[dict[str, Any]] = []
    complete = True
    if not lb_arn:
        return targets, False
    try:
        for page in client.get_paginator("describe_target_groups").paginate(LoadBalancerArn=lb_arn):
            for group in page.get("TargetGroups", []) or []:
                group_arn = str(group.get("TargetGroupArn") or "")
                if not group_arn:
                    complete = False
                    continue
                try:
                    response = client.describe_target_health(TargetGroupArn=group_arn)
                    for description in response.get("TargetHealthDescriptions", []) or []:
                        target = description.get("Target") or {}
                        if not target.get("Id"):
                            complete = False
                            continue
                        targets.append(
                            {
                                "target_id": str(target["Id"]),
                                "target_type": str(group.get("TargetType") or ""),
                                "target_group_arn": group_arn,
                                "port": target.get("Port"),
                                "protocol": str(group.get("Protocol") or ""),
                                "vpc_id": str(group.get("VpcId") or ""),
                                "health_state": str((description.get("TargetHealth") or {}).get("State") or ""),
                            }
                        )
                except Exception as exc:  # broad-except: SDK boundary preserves other groups and records sanitized partial coverage
                    complete = False
                    record_discovery_failure(
                        exc=exc,
                        resource_type="load balancer targets",
                        permission="elasticloadbalancing:DescribeTargetHealth",
                        cloud="aws",
                        warnings=warnings,
                        missing=missing,
                    )
    except Exception as exc:  # broad-except: SDK boundary retains the load balancer when backend discovery fails
        complete = False
        record_discovery_failure(
            exc=exc,
            resource_type="load balancer target groups",
            permission="elasticloadbalancing:DescribeTargetGroups",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return targets, complete


def _discover_elb(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate ALB/NLB load balancers (read-only). Internet-facing scheme = exposed."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("elbv2", region_name=region)
        paginator = client.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                name = str(lb.get("LoadBalancerName", "") or "")
                if not name:
                    continue
                targets, targets_complete = _discover_elb_targets(
                    client, str(lb.get("LoadBalancerArn") or ""), warnings=warnings, missing=missing
                )
                out.append(
                    {
                        "name": name,
                        "arn": str(lb.get("LoadBalancerArn", "") or ""),
                        "scheme": str(lb.get("Scheme", "") or ""),
                        "lb_type": str(lb.get("Type", "") or ""),
                        "internet_exposed": str(lb.get("Scheme", "")).lower() == "internet-facing",
                        "dns_name": str(lb.get("DNSName", "") or ""),
                        "vpc_id": str(lb.get("VpcId", "") or ""),
                        "account_id": account_id or "",
                        "location": region,
                        "backend_targets": targets,
                        "backend_collection_complete": targets_complete,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed ELB list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="load balancers",
            permission="elasticloadbalancing:DescribeLoadBalancers",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _discover_cloudfront(
    session: Any, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate CloudFront CDN distributions (read-only, global). Internet-facing edge."""
    out: list[dict[str, Any]] = []
    try:
        client = session.client("cloudfront")
        paginator = client.get_paginator("list_distributions")
        for page in paginator.paginate():
            for dist in (page.get("DistributionList", {}) or {}).get("Items", []) or []:
                dist_id = str(dist.get("Id", "") or "")
                if not dist_id:
                    continue
                origins = [str(o.get("DomainName", "")) for o in (dist.get("Origins", {}) or {}).get("Items", []) or []]
                out.append(
                    {
                        "name": dist_id,
                        "arn": str(dist.get("ARN", "") or ""),
                        "domain_name": str(dist.get("DomainName", "") or ""),
                        "enabled": bool(dist.get("Enabled")),
                        "internet_exposed": True,  # a CDN distribution is internet-facing by definition
                        "origins": origins,
                        "account_id": account_id or "",
                        "location": "global",
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed CloudFront list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="CloudFront distributions",
            permission="cloudfront:ListDistributions",
            cloud="aws",
            warnings=warnings,
            missing=missing,
        )
    return out


def _discover_messaging(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate SNS topics + SQS queues (read-only). Become messaging resources."""
    out: list[dict[str, Any]] = []
    try:
        sns = session.client("sns", region_name=region)
        paginator = sns.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                arn = str(topic.get("TopicArn", "") or "")
                if not arn:
                    continue
                out.append(
                    {
                        "name": arn.rsplit(":", 1)[-1],
                        "arn": arn,
                        "messaging_type": "sns-topic",
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed SNS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="SNS topics", permission="sns:ListTopics", cloud="aws", warnings=warnings, missing=missing
        )
    try:
        sqs = session.client("sqs", region_name=region)
        paginator = sqs.get_paginator("list_queues")
        for page in paginator.paginate():
            for url in page.get("QueueUrls", []) or []:
                name = str(url).rsplit("/", 1)[-1]
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "arn": f"arn:aws:sqs:{region}:{account_id or ''}:{name}",
                        "messaging_type": "sqs-queue",
                        "url": str(url),
                        "account_id": account_id or "",
                        "location": region,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed SQS list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="SQS queues", permission="sqs:ListQueues", cloud="aws", warnings=warnings, missing=missing
        )
    return out


def _discover_waf(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate WAFv2 web ACLs and the resources they front (read-only).

    Both scopes are covered: ``REGIONAL`` (ALB / API Gateway / AppSync in the
    region) and ``CLOUDFRONT`` (global edge, enumerated only from us-east-1 so a
    multi-region scan does not duplicate it). ``protected_targets`` carries the
    ARNs of the resources each web ACL is associated with, which the graph turns
    into ``PROTECTS`` edges that refine the fronted resource's exposure verdict.
    """
    out: list[dict[str, Any]] = []
    scopes = ["REGIONAL"]
    if region == "us-east-1":
        scopes.append("CLOUDFRONT")
    for scope in scopes:
        try:
            client = session.client("wafv2", region_name="us-east-1" if scope == "CLOUDFRONT" else region)
            next_marker: str | None = None
            while True:
                list_kwargs: dict[str, str] = {"Scope": scope}
                if next_marker:
                    list_kwargs["NextMarker"] = next_marker
                resp = client.list_web_acls(**list_kwargs)
                for acl in resp.get("WebACLs", []) or []:
                    name = str(acl.get("Name", "") or "")
                    arn = str(acl.get("ARN", "") or "")
                    if not (name or arn):
                        continue
                    targets: list[str] = []
                    # Regional web ACLs expose their associated resources directly;
                    # CloudFront associations are read from the distribution side and are
                    # left empty here to avoid a per-distribution describe storm.
                    if scope == "REGIONAL" and arn:
                        try:
                            assoc_marker: str | None = None
                            while True:
                                assoc_kwargs: dict[str, str] = {"WebACLArn": arn}
                                if assoc_marker:
                                    assoc_kwargs["NextMarker"] = assoc_marker
                                assoc = client.list_resources_for_web_acl(**assoc_kwargs)
                                targets.extend(str(r) for r in assoc.get("ResourceArns", []) or [] if r)
                                assoc_marker = assoc.get("NextMarker")
                                if not assoc_marker:
                                    break
                        except Exception as exc:  # noqa: BLE001 — association read is best-effort
                            warnings.append(f"Could not list resources for WAF {name}: {sanitize_discovery_warning(exc)}")
                    out.append(
                        {
                            "name": name or arn.rsplit("/", 1)[-1],
                            "id": str(acl.get("Id", "") or ""),
                            "arn": arn,
                            "scope": scope.lower(),
                            "protected_targets": targets,
                            "location": "global" if scope == "CLOUDFRONT" else region,
                            "account_id": account_id or "",
                        }
                    )
                next_marker = resp.get("NextMarker")
                if not next_marker:
                    break
        except Exception as exc:  # noqa: BLE001 — one failed WAF list must not sink the scan
            record_discovery_failure(
                exc=exc,
                resource_type=f"WAF web ACLs ({scope})",
                permission="wafv2:ListWebACLs",
                cloud="aws",
                warnings=warnings,
                missing=missing,
            )
            continue
    return out


def _discover_api_gateways(
    session: Any, region: str, *, account_id: str | None, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate REST (apigateway) and HTTP/WebSocket (apigatewayv2) APIs (read-only).

    Each API is internet-facing by default, so it becomes an ``API_GATEWAY``
    graph node in the API_GATEWAY semantic layer; ``stages`` carries the deployed
    stage names (non-secret) for context.
    """
    out: list[dict[str, Any]] = []
    try:
        rest = session.client("apigateway", region_name=region)
        paginator = rest.get_paginator("get_rest_apis")
        for page in paginator.paginate():
            for api in page.get("items", []) or []:
                api_id = str(api.get("id", "") or "")
                if not api_id:
                    continue
                stages: list[str] = []
                try:
                    for stage in rest.get_stages(restApiId=api_id).get("item", []) or []:
                        stage_name = str(stage.get("stageName", "") or "")
                        if stage_name:
                            stages.append(stage_name)
                except Exception:  # noqa: BLE001 — stage read is best-effort
                    stages = []
                endpoint_types = [str(t) for t in ((api.get("endpointConfiguration") or {}).get("types") or [])]
                out.append(
                    {
                        "name": str(api.get("name", "") or api_id),
                        "id": api_id,
                        "arn": "",
                        "protocol": "REST",
                        "endpoint": ",".join(endpoint_types),
                        "internet_exposed": "PRIVATE" not in endpoint_types,
                        "stages": stages,
                        "protected_targets": [],
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed API Gateway list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="API Gateway REST APIs", permission="apigateway:GET", cloud="aws", warnings=warnings, missing=missing
        )

    try:
        v2 = session.client("apigatewayv2", region_name=region)
        next_token: str | None = None
        while True:
            resp = v2.get_apis(NextToken=next_token) if next_token else v2.get_apis()
            for api in resp.get("Items", []) or []:
                api_id = str(api.get("ApiId", "") or "")
                if not api_id:
                    continue
                out.append(
                    {
                        "name": str(api.get("Name", "") or api_id),
                        "id": api_id,
                        "arn": "",
                        "protocol": str(api.get("ProtocolType", "") or "HTTP"),
                        "endpoint": str(api.get("ApiEndpoint", "") or ""),
                        "internet_exposed": True,
                        "stages": [],
                        "protected_targets": [],
                        "location": region,
                        "account_id": account_id or "",
                    }
                )
            next_token = resp.get("NextToken")
            if not next_token:
                break
    except Exception as exc:  # noqa: BLE001 — one failed API Gateway v2 list must not sink the scan
        record_discovery_failure(
            exc=exc, resource_type="API Gateway HTTP/WS APIs", permission="apigateway:GET", cloud="aws", warnings=warnings, missing=missing
        )
    return out
