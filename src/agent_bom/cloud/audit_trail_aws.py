"""AWS audit identity and outcome projection without retaining raw event contents."""

from __future__ import annotations

import json
from typing import Any


def aws_event_outcome(raw: dict[str, Any], action: str) -> str:
    # LookupEvents wraps the provider outcome in a JSON string. Keep only its
    # classification; error messages and request/response content are not retained.
    document = raw.get("CloudTrailEvent")
    if not isinstance(document, str) or len(document) > 1_000_000:
        return "unknown"
    try:
        detail = json.loads(document)
    except (ValueError, TypeError):
        return "unknown"
    if not isinstance(detail, dict):
        return "unknown"
    if detail.get("errorCode") or detail.get("errorMessage"):
        return "failure"
    if action.lower().startswith("invoke"):
        response = detail.get("responseElements")
        if isinstance(response, dict) and response.get("statusCode") == 202:
            return "accepted"
        # HTTP 200 does not report Lambda function errors; a separate execution
        # receipt is needed. DryRun and missing response metadata prove no call.
        return "unknown"
    return "success"


def _clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def aws_event_fields(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    action = _clean(raw.get("EventName"))
    principal = _clean(raw.get("Username"))
    resources = raw.get("Resources") or []
    resource = ""
    if isinstance(resources, list) and resources and isinstance(resources[0], dict):
        resource = _clean(resources[0].get("ResourceName") or resources[0].get("ResourceType"))
    resource = resource or _clean(raw.get("EventSource"))
    if not principal or not action or not resource:
        return None
    return {"principal": principal, "action": action, "resource": resource, "outcome": aws_event_outcome(raw, action)}
