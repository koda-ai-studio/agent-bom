"""Unified findings for secrets found in a container image's layers, ENV and build history."""

from __future__ import annotations

from typing import Any

from agent_bom.finding import Finding, secret_dict_to_finding, stable_id
from agent_bom.image_evidence.model import as_list
from agent_bom.security import sanitize_text

__all__ = ["image_secret_findings", "secret_dict_to_finding"]


def image_metadata(agent: Any) -> dict[str, Any] | None:
    metadata = getattr(agent, "metadata", None)
    image = metadata.get("image") if isinstance(metadata, dict) else None
    return image if isinstance(image, dict) else None


def _secret_location(secret: dict[str, Any]) -> str:
    if secret.get("location_kind") == "layer":
        return f"/{secret.get('image_path', '')}"
    return str(secret.get("file") or "image config")


def image_secret_findings(agent: Any) -> list[Finding]:
    """Unified secret findings for one image agent, bound to its image server node."""
    image = image_metadata(agent)
    if image is None:
        return []
    reference = str(image.get("reference") or getattr(agent, "name", ""))
    servers = getattr(agent, "mcp_servers", None) or []
    image_node_identity = servers[0].stable_id if servers else getattr(agent, "stable_id", "")
    findings: list[Finding] = []
    for secret in as_list(image.get("secrets")):
        if not isinstance(secret, dict):
            continue
        location = _secret_location(secret)
        finding = secret_dict_to_finding({**secret, "file": f"{reference}:{location}"})
        layer = secret.get("layer_digest") or secret.get("location_kind") or ""
        finding.id = stable_id(
            "image-secret", reference, str(layer), location, str(secret.get("line") or ""), finding.evidence["secret_type"]
        )
        # The image is the scanned SERVER node (surface container-image); no location, so
        # repository overlays never mistake ``<image>:<path>`` for a repo file or application.
        finding.asset.asset_type = "server"
        finding.asset.identifier = image_node_identity or reference
        finding.asset.location = None
        finding.evidence.update(
            {
                "image": sanitize_text(reference, max_len=300),
                "image_digest": image.get("digest"),
                "location_kind": secret.get("location_kind"),
                "layer_index": secret.get("layer_index"),
                "layer_digest": secret.get("layer_digest"),
                "in_final_filesystem": secret.get("in_final_filesystem", True),
                **({"removed_in_layer": secret["removed_in_layer"]} if secret.get("removed_in_layer") else {}),
            }
        )
        if secret.get("in_final_filesystem") is False:
            finding.description += " The file was deleted or overwritten in a later layer, but the value is still in this layer's blob."
        findings.append(finding)
    return findings
