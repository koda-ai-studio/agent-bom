"""Model artifact coverage summaries and signature/format policy evaluation."""

from __future__ import annotations

from pathlib import Path

_UNSAFE_MODEL_EXTENSIONS = frozenset({".pt", ".pth", ".pkl", ".joblib", ".bin"})


def summarize_model_supply_chain(
    model_files: list[dict],
    model_provenance: list[dict] | None = None,
    model_hash_verification: dict | None = None,
    model_manifests: list[dict] | None = None,
) -> dict:
    """Build a stable summary of model/weight supply-chain coverage.

    This consolidates local model artifact scanning, HuggingFace provenance
    checks, and optional hash verification into one operator-facing contract
    that can be surfaced consistently in CLI, JSON, and docs.
    """
    provenance = model_provenance or []
    hash_verification = model_hash_verification or {}
    manifests = model_manifests or []

    provenance_with_flags = sum(1 for item in provenance if item.get("security_flags"))
    provenance_with_digest = sum(1 for item in provenance if item.get("has_digest") is True or item.get("sha256_available") is True)
    gated_models = sum(1 for item in provenance if item.get("is_gated") is True or item.get("gated") is True)
    sources = sorted({str(item.get("source", "huggingface")) for item in provenance})
    model_advisories: list[dict] = []
    for item in provenance:
        advisories = item.get("model_advisories", [])
        if not isinstance(advisories, list):
            continue
        model_advisories.extend(advisory for advisory in advisories if isinstance(advisory, dict))
    advisory_severities = sorted({str(item.get("severity", "unknown")) for item in model_advisories})
    manifest_types = sorted({str(item.get("manifest_type")) for item in manifests if item.get("manifest_type")})

    from agent_bom.model_advisories import feed_posture

    return {
        **_local_artifact_summary(model_files),
        "provenance_checks": len(provenance),
        "provenance_with_digest": provenance_with_digest,
        "gated_models": gated_models,
        "provenance_with_security_flags": provenance_with_flags,
        "provenance_sources": sources,
        "ai_model_advisories": {
            "count": len(model_advisories),
            "severities": advisory_severities,
            "items": model_advisories,
            "feed": feed_posture(),
        },
        "manifest_files": len(manifests),
        "manifest_types": manifest_types,
        "manifests_with_repo_id": sum(1 for item in manifests if item.get("repo_id")),
        "adapter_lineage_refs": sum(1 for item in manifests if item.get("base_model_id")),
        "sharded_bundles": sum(1 for item in manifests if int(item.get("shard_count", 0) or 0) > 0),
        "manifests_with_security_flags": sum(1 for item in manifests if item.get("security_flags")),
        "hash_verification": {
            "scanned": int(hash_verification.get("scanned", 0) or 0),
            "verified": int(hash_verification.get("verified", 0) or 0),
            "tampered": int(hash_verification.get("tampered", 0) or 0),
            "unverified": int(hash_verification.get("unverified", 0) or 0),
            "offline": int(hash_verification.get("offline", 0) or 0),
            "has_tampering": bool(hash_verification.get("has_tampering", False)),
        },
    }


def evaluate_model_provenance_policy(
    model_files: list[dict],
    *,
    mode: str = "warn",
    require_signatures: bool = False,
    block_unsafe_formats: bool = False,
) -> dict:
    """Evaluate local model artifact policy without inventing new signing.

    The evaluator consumes fields already produced by ``scan_model_files`` and
    ``check_sigstore_signature``. ``warn`` mode reports violations without
    blocking; ``enforce`` mode marks the policy as failed.
    """

    normalized_mode = mode if mode in {"off", "warn", "enforce"} else "warn"
    violations: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    if normalized_mode == "off":
        return {
            "mode": "off",
            "passed": True,
            "require_signatures": require_signatures,
            "block_unsafe_formats": block_unsafe_formats,
            "violations": [],
            "warnings": [],
            "checked_files": len(model_files),
        }

    for model_file in model_files:
        filename = str(model_file.get("filename") or Path(str(model_file.get("path", "model"))).name)
        extension = str(model_file.get("extension", "")).lower()
        if require_signatures and model_file.get("signed") is not True:
            violations.append(
                {
                    "type": "UNSIGNED_MODEL",
                    "severity": "HIGH",
                    "file": filename,
                    "message": "model artifact has no Sigstore/cosign-compatible signature evidence",
                }
            )
        if block_unsafe_formats and extension in _UNSAFE_MODEL_EXTENSIONS:
            violations.append(
                {
                    "type": "UNSAFE_MODEL_FORMAT",
                    "severity": "HIGH",
                    "file": filename,
                    "message": f"model artifact uses unsafe or executable-on-load format {extension}",
                }
            )

    if normalized_mode == "warn":
        warnings = violations
        violations = []

    return {
        "mode": normalized_mode,
        "passed": not violations,
        "require_signatures": require_signatures,
        "block_unsafe_formats": block_unsafe_formats,
        "violations": violations,
        "warnings": warnings,
        "checked_files": len(model_files),
    }


def _local_artifact_summary(model_files: list[dict]) -> dict:
    files_with_flags = 0
    signed_files = 0
    unsigned_files = 0
    unsafe_files = 0
    total_size_bytes = 0
    ecosystems: set[str] = set()
    formats: set[str] = set()

    for model_file in model_files:
        total_size_bytes += int(model_file.get("size_bytes", 0) or 0)
        if model_file.get("security_flags"):
            files_with_flags += 1
        if model_file.get("signed") is True:
            signed_files += 1
        else:
            unsigned_files += 1
        if str(model_file.get("extension", "")).lower() in _UNSAFE_MODEL_EXTENSIONS:
            unsafe_files += 1
        ecosystem = model_file.get("ecosystem")
        if ecosystem:
            ecosystems.add(str(ecosystem))
        fmt = model_file.get("format")
        if fmt:
            formats.add(str(fmt))

    return {
        "model_files": len(model_files),
        "total_size_bytes": total_size_bytes,
        "signed_files": signed_files,
        "unsigned_files": unsigned_files,
        "unsafe_format_files": unsafe_files,
        "files_with_security_flags": files_with_flags,
        "formats": sorted(formats),
        "ecosystems": sorted(ecosystems),
    }
