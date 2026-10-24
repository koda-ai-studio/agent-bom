"""Globally unique demo names for object stores, which share one namespace per cloud."""

from __future__ import annotations

import hashlib
import re


def globally_unique_name(resource_type: str, name: str, scope: str) -> str:
    """Object-store names are one namespace per cloud, not per account.

    S3/GCS buckets become ``<name>-<account>``. Azure storage accounts allow
    only 3-24 lowercase letters and digits, so they keep a stable hash suffix.
    """
    if resource_type == "bucket":
        return f"{name}-{scope}"
    if resource_type == "storage_account":
        suffix = hashlib.sha256(f"{scope}:{name}".encode()).hexdigest()[:6]
        return re.sub(r"[^a-z0-9]", "", name.lower())[:18] + suffix
    return name
