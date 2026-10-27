"""Image evidence on every surface: findings, graph node attributes, console lines, policy."""

from __future__ import annotations

from typing import Any

from agent_bom.image_evidence.model import ImageEvidence, as_dict, as_list
from agent_bom.security import sanitize_text

IMAGE_SURFACES = frozenset({"container-image", "oci-tarball"})
_SIGNATURE_STYLE = {"verified": "green", "present-unverified": "yellow", "unsigned": "yellow", "invalid": "red", "unknown": "dim"}


def image_agent_metadata(evidence: ImageEvidence) -> dict[str, Any]:
    return {"image": evidence.to_metadata()}


def image_node_attributes(agent_metadata: dict[str, Any], surface: str) -> dict[str, Any]:
    """Compact image evidence for the image's graph node (``attributes['image']``)."""
    image = as_dict(agent_metadata.get("image")) if surface in IMAGE_SURFACES else {}
    if not image:
        return {}
    signature, base = as_dict(image.get("signature")), as_dict(image.get("base_image"))
    referrers = [r for r in as_list(image.get("referrers")) if isinstance(r, dict)]
    return {
        "image": {
            "reference": image.get("reference"),
            "source": image.get("source"),
            "digest": image.get("digest"),
            "index_digest": image.get("index_digest"),
            "platform": image.get("platform"),
            "signature_status": signature.get("status", "unknown"),
            "signature_method": signature.get("method"),
            "base_image": base.get("name"),
            "base_image_digest": base.get("digest"),
            "base_attribution": base.get("attribution"),
            "referrer_kinds": sorted({str(r.get("kind")) for r in referrers}),
            "secret_count": len(as_list(image.get("secrets"))),
        }
    }


def signature_policy_violation(evidence: ImageEvidence, require: bool) -> str | None:
    """Reason the image fails ``--require-image-signature`` (``None`` when it passes or the gate is off)."""
    if not require:
        return None
    status = str(evidence.signature.get("status") or "unknown")
    if not evidence.cosign_key_path:
        return f"image signature is {status}; a cosign public key is required to enforce signatures (pass --image-cosign-key)"
    if status == "verified":
        return None
    return f"image signature is {status} (a verified signature is required with --image-cosign-key)"


def console_lines(evidence: ImageEvidence) -> list[str]:
    """Rich-markup summary lines printed under an image's package count."""
    signature = evidence.signature
    status = str(signature.get("status") or "unknown")
    detail = sanitize_text(signature.get("detail", ""), max_len=160)
    lines = [f"    signature: [{_SIGNATURE_STYLE.get(status, 'dim')}]{status}[/] [dim]{detail}[/dim]"]
    if evidence.digest:
        platform = f" {evidence.platform}" if evidence.platform else ""
        lines.append(f"    digest: [dim]{evidence.digest}{platform} (via {evidence.source})[/dim]")
    if evidence.referrers:
        kinds = ", ".join(sorted({str(r["kind"]) for r in evidence.referrers}))
        lines.append(f"    attached artifacts: {len(evidence.referrers)} [dim]({kinds})[/dim]")
    base = evidence.base_image
    if base:
        split = (
            f" — {base.get('packages_from_base', 0)} package(s) from base, {base.get('packages_from_app', 0)} from app layers"
            if base.get("attribution") == "layer-digest-match"
            else f" [dim]({base.get('attribution')})[/dim]"
        )
        lines.append(f"    base image: {sanitize_text(base.get('name') or base.get('digest'), max_len=200)}{split}")
    secrets = [*evidence.config_secrets, *evidence.layer_secrets]
    if secrets:
        lines.append(f"    [red]secrets: {len(secrets)} hardcoded secret(s) in image layers/config (values redacted)[/red]")
    return lines
