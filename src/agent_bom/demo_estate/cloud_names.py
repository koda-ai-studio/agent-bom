"""Globally unique demo names for resources whose names share one namespace per cloud."""

from __future__ import annotations

import hashlib
import re


def globally_unique_name(resource_type: str, name: str, scope: str) -> str:
    """Object-store names are one namespace per cloud, not per account.

    S3/GCS buckets become ``<name>-<account>``. Azure storage accounts allow
    only 3-24 lowercase letters and digits, so they keep a stable hash suffix.
    Azure function apps answer on ``<name>.azurewebsites.net`` (2-60 letters,
    digits and inner hyphens), so they keep a hyphenated hash suffix.
    """
    if resource_type == "bucket":
        return f"{name}-{scope}"
    if resource_type == "storage_account":
        suffix = hashlib.sha256(f"{scope}:{name}".encode()).hexdigest()[:6]
        return re.sub(r"[^a-z0-9]", "", name.lower())[:18] + suffix
    if resource_type == "function_app":
        suffix = hashlib.sha256(f"{scope}:{name}".encode()).hexdigest()[:6]
        stem = re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]", "-", name.lower())).strip("-")[:53]
        return f"{stem}-{suffix}"
    return name
