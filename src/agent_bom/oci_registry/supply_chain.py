"""Signature, referrer and base-image evidence for one image digest (read-only)."""

from __future__ import annotations

from typing import Any

from agent_bom.image_evidence.base_image import match_base_layers
from agent_bom.image_evidence.model import ImageEvidence
from agent_bom.oci_registry.client import RegistryClient, RegistryError
from agent_bom.oci_registry.manifests import resolve_image_manifest
from agent_bom.oci_registry.platforms import PlatformNotFoundError
from agent_bom.oci_registry.reference import ReferenceError, parse_reference
from agent_bom.oci_registry.referrers import discover_referrers
from agent_bom.oci_registry.signatures import SignatureKeyError, fetch_cosign_signatures, load_public_key, signature_verdict


def _candidate_digests(evidence: ImageEvidence) -> list[str]:
    return list(dict.fromkeys(d for d in (evidence.index_digest, evidence.digest) if d))


def _signature_status(client: RegistryClient, evidence: ImageEvidence, digests: list[str]) -> dict[str, Any]:
    key = None
    if evidence.cosign_key_path:
        try:
            key = load_public_key(evidence.cosign_key_path)
        except SignatureKeyError as exc:
            return {"status": "unknown", "detail": str(exc)}
    signatures = [sig for digest in digests for sig in fetch_cosign_signatures(client, digest)]
    if signatures:
        return signature_verdict(signatures, digests, key)
    bundles = [r for r in evidence.referrers if r["kind"] == "signature"]
    if bundles:
        return {
            "status": "invalid" if key is not None else "present-unverified",
            "method": "sigstore-bundle",
            "detail": "A Sigstore bundle is attached as an OCI referrer; bundle verification is not performed"
            + (", so the provided key could not verify it." if key is not None else "."),
        }
    return {"status": "unsigned", "detail": "No cosign signature tag or Sigstore bundle referrer exists for this image digest."}


def discover_supply_chain(client: RegistryClient, evidence: ImageEvidence, index: dict[str, Any] | None) -> None:
    """Fill ``evidence.referrers`` and ``evidence.signature``; registry errors become ``unknown``."""
    digests = _candidate_digests(evidence)
    if not digests:
        evidence.signature = {"status": "unknown", "detail": "The image digest is not known, so signatures could not be looked up."}
        return
    try:
        evidence.referrers = discover_referrers(client, digests, index)
        evidence.signature = _signature_status(client, evidence, digests)
    except RegistryError as exc:
        evidence.signature = {"status": "unknown", "detail": f"Signature lookup failed: {exc}"}


def resolve_base_layers(evidence: ImageEvidence, open_client: Any) -> None:
    """Fetch the named base image's layer list and attribute layers when it is an exact prefix."""
    base = evidence.base_image
    if base is None or not (base.get("name") or base.get("digest")):
        return
    name = str(base.get("name") or "")
    try:
        ref = parse_reference(f"{name.split('@', 1)[0]}@{base['digest']}" if base.get("digest") and name else name)
    except ReferenceError:
        base["attribution"] = "unresolved"
        return
    try:
        with open_client(ref) as client:
            manifest, _index, _platform, _available = resolve_image_manifest(client, ref, evidence.platform)
            config = client.fetch_json_blob(str(manifest.document.get("config", {}).get("digest") or ""))
    except (RegistryError, PlatformNotFoundError) as exc:
        base["attribution"] = "unresolved"
        evidence.note(f"Base image {name or base.get('digest')} could not be fetched for layer attribution: {exc}")
        return
    rootfs = config.get("rootfs") if isinstance(config.get("rootfs"), dict) else {}
    diff_ids = [d for d in rootfs.get("diff_ids") or [] if isinstance(d, str)]
    match_base_layers(evidence, diff_ids)
