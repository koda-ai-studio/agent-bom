"""Fixed public diagnostics for Kubernetes collection failures.

Stderr may contain credentials, endpoints and local paths. Inspect it only to
classify a failure; never return its contents as inventory evidence.
"""

from __future__ import annotations


def kubectl_failure_code(stderr: str) -> str:
    text = stderr.lower()
    if "forbidden" in text:
        return "permission_denied"
    if "unauthorized" in text or "must be logged in" in text:
        return "invalid_credentials"
    if "doesn't have a resource type" in text or "could not find the requested resource" in text:
        return "resource_unavailable"
    if "timeout" in text or "deadline exceeded" in text:
        return "timeout"
    return "collection_failed"
