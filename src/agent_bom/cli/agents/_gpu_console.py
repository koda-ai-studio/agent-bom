"""Console summary of Kubernetes GPU workloads, their node stack and GPU posture."""

from __future__ import annotations

from collections import Counter
from typing import Any

_SEVERITY_STYLE = {"critical": "red", "high": "red", "medium": "yellow", "low": "dim", "info": "dim"}
_MAX_LISTED = 6


def print_gpu_workload_summary(con: Any, report: Any) -> None:
    """CUDA versions, workloads per pool, the declared/observed GPU stack and posture findings, most severe first."""
    if report.unique_cuda_versions:
        con.print(f"  CUDA versions: {', '.join(report.unique_cuda_versions)}")
    k8s = getattr(report, "k8s", None)
    if k8s is None or not k8s.workloads:
        return
    pools = Counter(w.pool_name or "unscheduled" for w in k8s.workloads)
    con.print(f"  [green]✓[/green] {len(k8s.workloads)} GPU workload(s) in {k8s.cluster_key} across {len(pools)} node pool(s)")
    for pool, count in sorted(pools.items()):
        con.print(f"    {pool}: {count} workload(s)")
    drivers = sorted({w.driver_version for w in k8s.workloads if w.driver_version} | ({k8s.stack.driver_version} - {""}))
    if drivers or k8s.stack.toolkit_version:
        toolkit = k8s.stack.toolkit_version or "not declared"
        drivers_text = ", ".join(drivers) or "not reported"
        con.print(f"  GPU stack: driver {drivers_text}; Container Toolkit {toolkit} (matched against NVD / NVIDIA advisories)")
    findings = sorted(report.posture_findings, key=lambda f: ("critical", "high", "medium", "low", "info").index(f["severity"]))
    if not findings:
        return
    con.print(f"  GPU posture: {len(findings)} finding(s)")
    for finding in findings[:_MAX_LISTED]:
        style = _SEVERITY_STYLE.get(finding["severity"], "dim")
        label = f"{finding['check_id']} {finding['title']} — {finding['asset_name']}"
        con.print(f"    [{style}]{finding['severity'].upper():<8}[/{style}] {label}")
    if len(findings) > _MAX_LISTED:
        con.print(f"    [dim]… {len(findings) - _MAX_LISTED} more in the findings report[/dim]")
