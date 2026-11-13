"""The sample estate's data-classifier results, recorded as a live scan records them."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

if TYPE_CHECKING:
    from agent_bom.demo_estate.enterprise import EstateAsset

# Regulated classes, most restrictive first: the label a data classifier
# records on a store whose sampled contents carry them.
_SENSITIVE_CLASSES = ("phi", "pci", "pii")


def record_data_classification(node: UnifiedNode, asset: EstateAsset) -> None:
    """Record the sample store's classifier result as a live scan would.

    Only data stores carry it, and only for regulated classes; ``confidential``
    is a handling label, not a classifier finding, so it records nothing.
    """
    if node.entity_type != EntityType.DATA_STORE:
        return
    recorded = {classification.lower() for classification in asset.data_classifications}
    label = next((cls for cls in _SENSITIVE_CLASSES if cls in recorded), None)
    if label is not None:
        node.attributes["data_sensitivity"] = label
        node.attributes["data_sensitivity_basis"] = ["recorded_classification"]


__all__ = ["record_data_classification"]
