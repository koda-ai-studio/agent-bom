"""Serialize a side-scan result into the report's ``side_scan_results`` section.

One record per scanned disk or machine image: where it was scanned, the VM
that owns it when the provider recorded one, and a bounded package/CVE
inventory. The same record feeds the JSON report, the API response, the MCP
tool and the graph, so every surface shows the same packages for a VM.
"""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

MAX_SIDE_SCAN_PACKAGES = 500
_SUMMARY_LIMIT = 300


def _vulnerability(vuln: Any) -> dict[str, Any]:
    severity = getattr(vuln, "severity", "")
    return {
        "id": str(vuln.id),
        "severity": str(getattr(severity, "value", severity) or "").lower(),
        "summary": sanitize_text(str(getattr(vuln, "summary", "") or ""), max_len=_SUMMARY_LIMIT),
        "cvss_score": getattr(vuln, "cvss_score", None),
        "fixed_version": getattr(vuln, "fixed_version", None),
        "is_kev": bool(getattr(vuln, "is_kev", False)),
        "epss_score": getattr(vuln, "epss_score", None),
        "vex_status": getattr(vuln, "vex_status", None),
    }


def _package(pkg: Any) -> dict[str, Any]:
    vulns = [_vulnerability(v) for v in getattr(pkg, "vulnerabilities", None) or []]
    return {
        "name": pkg.name,
        "version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "purl": pkg.purl or "",
        "source_package": getattr(pkg, "source_package", None) or "",
        "distro_name": getattr(pkg, "distro_name", None) or "",
        "distro_version": getattr(pkg, "distro_version", None) or "",
        "vulnerability_count": len(vulns),
        "vulnerabilities": vulns,
    }


def side_scan_packages(packages: list[Any], *, limit: int = MAX_SIDE_SCAN_PACKAGES) -> dict[str, Any]:
    """Vulnerable packages first, capped with an explicit truncation count."""
    ordered = sorted(packages, key=lambda pkg: (-len(getattr(pkg, "vulnerabilities", None) or []), pkg.name, pkg.version))
    kept = ordered[:limit]
    return {
        "package_count": len(packages),
        "vulnerability_count": sum(len(getattr(pkg, "vulnerabilities", None) or []) for pkg in packages),
        "vulnerable_package_count": sum(1 for pkg in packages if getattr(pkg, "vulnerabilities", None)),
        "packages": [_package(pkg) for pkg in kept],
        "packages_truncated": len(packages) > len(kept),
        "packages_omitted": len(packages) - len(kept),
    }


def _aws_record(result: Any) -> dict[str, Any]:
    image_id = str(getattr(result, "image_id", "") or "")
    volume_id = str(getattr(result, "volume_id", "") or "")
    region = str(getattr(result, "region", "") or "").strip()
    return {
        "provider": "aws",
        "target_type": "ami" if image_id else "ebs_volume",
        "target_id": image_id or volume_id,
        "account_id": str(getattr(result, "account_id", "") or ""),
        "region": region,
        "location": region,
        "instance_id": "" if image_id else str(getattr(result, "instance_id", "") or ""),
        "instance_name": "",
        "image_id": image_id,
        "execution_id": "",
        "snapshot_id": str(getattr(result, "snapshot_id", "") or ""),
        "cleaned_up": bool(getattr(result, "cleaned_up", False)),
        "replayed": False,
    }


def _provider_record(result: Any, provider: str) -> dict[str, Any]:
    target_type = str(getattr(result, "target_type", "") or "disk")
    target_id = str(getattr(result, "target_id", "") or "")
    return {
        "provider": provider,
        "target_type": target_type,
        "target_id": target_id,
        "account_id": str(getattr(result, "account_id", "") or ""),
        "region": "",
        "location": str(getattr(result, "location", "") or ""),
        "instance_id": str(getattr(result, "instance_id", "") or ""),
        "instance_name": str(getattr(result, "instance_name", "") or ""),
        "image_id": target_id if target_type == "image" else "",
        "execution_id": str(getattr(result, "execution_id", "") or ""),
        "snapshot_id": str(getattr(result, "snapshot_id", "") or ""),
        "cleaned_up": bool(getattr(result, "cleaned_up", False)),
        "replayed": bool(getattr(result, "replayed", False)),
    }


def side_scan_record(result: Any, *, provider: str, limit: int = MAX_SIDE_SCAN_PACKAGES) -> dict[str, Any]:
    """The report record for one AWS ``SideScanResult`` or Azure/GCP execution result."""
    record = _aws_record(result) if provider == "aws" else _provider_record(result, provider)
    record.update(side_scan_packages(list(getattr(result, "packages", None) or []), limit=limit))
    counts = getattr(result, "recorded_counts", None)
    if record.get("replayed") and isinstance(counts, dict):
        # A replay holds durable counts only; never present it as an empty disk.
        record["package_count"] = int(counts.get("package_count", 0) or 0)
        record["vulnerability_count"] = int(counts.get("vulnerability_count", 0) or 0)
        record["packages_truncated"] = record["package_count"] > 0
        record["packages_omitted"] = record["package_count"]
    record["secret_count"] = len(getattr(result, "secrets", None) or [])
    record["warnings"] = [str(warning) for warning in getattr(result, "warnings", None) or []]
    return record


def side_scan_response(results: list[Any], *, provider: str = "") -> dict[str, Any]:
    """API / MCP summary of the first result: lifecycle metadata plus its bounded package record."""
    if not results:
        return {}
    res = results[0]
    counts = getattr(res, "recorded_counts", None) or {}
    record = side_scan_record(res, provider=provider or str(getattr(res, "provider", "") or "aws"))
    return {
        **record,
        "scan_disk_id": getattr(res, "scan_disk_id", None),
        "secret_count": counts.get("secret_count", record["secret_count"]),
        "config_finding_count": counts.get("config_finding_count", len(getattr(res, "config_findings", []) or [])),
        "ioc_finding_count": counts.get("ioc_finding_count", len(getattr(res, "ioc_findings", []) or [])),
    }
