"""Context counts over the bounded canonical current finding stream."""

from agent_bom.api.read_models._base import ReadModel, ReadResponse
from agent_bom.evidence.finding_context import FindingContext


class FindingContextCount(ReadModel):
    context: FindingContext
    total: int
    severity: dict[str, int]


class FindingContextResponse(ReadResponse):
    contexts: list[FindingContextCount]
    count: int
    approximate: bool
    warnings: list[str]
    basis: str
