"""Image evidence beyond the package inventory: provenance, signatures, base image, secrets."""

from agent_bom.image_evidence.model import ImageEvidence, active_image_evidence, collect_image_evidence

__all__ = ["ImageEvidence", "active_image_evidence", "collect_image_evidence"]
