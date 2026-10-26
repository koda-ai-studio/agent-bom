"""GPU capacity in managed data platforms: Snowflake SPCS compute pools and Databricks clusters.

Both platforms own the host GPU stack (driver and container runtime), so the
operator controls who shares the GPU nodes, not the driver version. The
records use the same keys as :mod:`agent_bom.cloud.gpu_node_pools`.
"""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.gpu_accelerators import databricks_node_accelerator, snowflake_instance_family_accelerator

# Databricks access modes in which several users run code on the same cluster.
_DATABRICKS_SHARED_MODES = frozenset(
    {"NONE", "USER_ISOLATION", "LEGACY_TABLE_ACL", "LEGACY_PASSTHROUGH", "DATA_SECURITY_MODE_STANDARD", "DATA_SECURITY_MODE_AUTO"}
)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None and str(value).strip() != "" else None
    except (TypeError, ValueError):
        return None


def snowflake_compute_pool(row: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize one ``SHOW COMPUTE POOLS`` row (lower-cased column names)."""
    name = str(row.get("name") or "")
    if not name:
        return None
    family = str(row.get("instance_family") or "")
    acc = snowflake_instance_family_accelerator(family)
    return {
        "name": name,
        "pool_id": name,
        "pool_kind": "spcs-compute-pool",
        "provider": "snowflake",
        "instance_family": family,
        "machine_types": [family] if family else [],
        "gpu": acc is not None,
        "gpu_vendor": acc.vendor if acc else "",
        "accelerator_type": acc.model if acc else "",
        "accelerators_per_node": acc.count if acc else None,
        "host_cloud": acc.cloud if acc else "",
        "state": str(row.get("state") or ""),
        "min_nodes": _int_or_none(row.get("min_nodes")),
        "max_nodes": _int_or_none(row.get("max_nodes")),
        "node_count": _int_or_none(row.get("active_nodes")),
        "num_services": _int_or_none(row.get("num_services")) or 0,
        "num_jobs": _int_or_none(row.get("num_jobs")) or 0,
        "auto_suspend_secs": _int_or_none(row.get("auto_suspend_secs")),
        "owner": str(row.get("owner") or ""),
        "application": str(row.get("application") or ""),
        "is_exclusive": str(row.get("is_exclusive") or "").strip().lower() in {"true", "y", "yes"},
        "gpu_driver": {"management": "provider-managed", "setting": "snowflake-managed"} if acc else {"management": "not-applicable"},
        "gpu_sharing": {"strategy": "shared-by-services"}
        if acc and (_int_or_none(row.get("num_services")) or 0) > 1
        else {"strategy": "none"},
    }


def _sdk_str(value: Any) -> str:
    raw = getattr(value, "value", value)
    return raw if isinstance(raw, str) else ""


def databricks_node_gpu_counts(ws: Any) -> dict[str, int]:
    """``node_type_id -> num_gpus`` from the workspace's node-type listing; empty when unavailable."""
    try:
        listing = ws.clusters.list_node_types()
    except Exception:  # noqa: BLE001 — the listing only refines counts; names still classify
        return {}
    counts: dict[str, int] = {}
    for node_type in getattr(listing, "node_types", None) or []:
        node_id = _sdk_str(getattr(node_type, "node_type_id", ""))
        gpus = getattr(node_type, "num_gpus", None)
        if node_id and isinstance(gpus, int):
            counts[node_id] = gpus
    return counts


def databricks_gpu_profile(cluster: Any, node_gpus: dict[str, int]) -> dict[str, Any] | None:
    """GPU profile of a Databricks cluster, or ``None`` when its workers carry no GPU."""
    worker = _sdk_str(getattr(cluster, "node_type_id", ""))
    driver = _sdk_str(getattr(cluster, "driver_node_type_id", "")) or worker
    acc = databricks_node_accelerator(worker, reported_gpus=node_gpus.get(worker)) if worker else None
    if acc is None:
        return None
    runtime = _sdk_str(getattr(cluster, "spark_version", ""))
    mode = _sdk_str(getattr(cluster, "data_security_mode", ""))
    autoscale = getattr(cluster, "autoscale", None)
    workers = getattr(cluster, "num_workers", None)
    if mode == "NONE":
        sharing = "multi-user-no-isolation"
    elif mode in _DATABRICKS_SHARED_MODES:
        sharing = "multi-user"
    else:
        sharing = "single-user" if mode else "unknown"
    return {
        "name": _sdk_str(getattr(cluster, "cluster_name", "")),
        "pool_id": _sdk_str(getattr(cluster, "cluster_id", "")),
        "pool_kind": "databricks-cluster",
        "provider": "databricks",
        "machine_types": sorted({worker, driver} - {""}),
        "gpu": True,
        "gpu_vendor": acc.vendor,
        "accelerator_type": acc.model,
        "accelerators_per_node": acc.count,
        "min_nodes": _int_or_none(getattr(autoscale, "min_workers", None)) if autoscale is not None else None,
        "max_nodes": _int_or_none(getattr(autoscale, "max_workers", None)) if autoscale is not None else None,
        "node_count": _int_or_none(workers) if isinstance(workers, int) else None,
        "runtime": runtime,
        "gpu_runtime": "-gpu-" in runtime,
        "data_security_mode": mode,
        "single_user": bool(_sdk_str(getattr(cluster, "single_user_name", ""))),
        "gpu_driver": {"management": "provider-managed", "setting": runtime or "databricks-runtime"},
        "gpu_sharing": {"strategy": sharing},
    }
