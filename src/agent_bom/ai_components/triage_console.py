"""Terminal summary of AI advice. Model text is printed as text, so it cannot style or link anything."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.text import Text

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport

_MAX_SHOWN = 10
_VERDICT_WORDS = (("likely_false_positive", "likely false positive"), ("confirmed", "confirmed"), ("needs_review", "needs review"))


def render_ai_triage_summary(report: "AIBOMReport", console: Console) -> None:
    metadata = getattr(report, "ai_enrichment_metadata", None) or {}
    status = str(metadata.get("status") or "")
    assessments = list(getattr(report, "ai_finding_assessments", None) or [])
    console.print(Text("AI advice (does not change scanner severity or results)", style="bold"))
    if status in {"failed", "blocked", "unavailable", "disabled"} and not assessments:
        console.print(Text(f"  {status}: {metadata.get('reason') or 'no assessments'}. Scanner results are unaffected."))
        return
    counts = {word: sum(item.verdict == verdict for item in assessments) for verdict, word in _VERDICT_WORDS}
    console.print(Text("  " + ", ".join(f"{count} {word}" for word, count in counts.items())))
    scope = metadata.get("triage_scope")
    skipped = scope.get("skipped") if isinstance(scope, dict) else None
    skipped = skipped if isinstance(skipped, dict) else {}
    left_out = sum(int(value) for value in skipped.values())
    if left_out:
        reasons = ", ".join(f"{name.replace('_', ' ')}: {value}" for name, value in sorted(skipped.items()))
        console.print(Text(f"  {left_out} not assessed ({reasons})"))
    guarded = sum(1 for item in assessments if item.guard_applied)
    if guarded:
        console.print(Text(f"  {guarded} model dismissal(s) of protected findings were discarded"))
    if assessments:
        first = assessments[0].provenance
        digest = f" {first.model_digest[:19]}" if first.model_digest else ""
        console.print(Text(f"  model: {first.model}{digest}, {first.generated_at.date().isoformat()}"))
    flagged = [item for item in assessments if item.verdict == "likely_false_positive"]
    for item in flagged[:_MAX_SHOWN]:
        console.print(Text(f"  - {item.finding_id[:24]} ({item.confidence}): {item.rationale}"))
    if len(flagged) > _MAX_SHOWN:
        console.print(Text(f"  ... and {len(flagged) - _MAX_SHOWN} more in the report"))
