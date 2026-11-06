"""How a triage model measured against the committed bar in ``tests/fixtures/ai_triage_eval/bar.json``.

Results are published in ``docs/AI_ENRICHMENT.md``. Standing follows the model name and
tag only: another build under the same tag, or the same model on another host, was not
measured separately.
"""

from __future__ import annotations

from typing import Literal

TriageModelStanding = Literal["met_bar", "missed_bar", "not_measured"]

_LOCAL_PREFIXES = ("ollama/", "ollama_chat/")
_MET_BAR = frozenset({"qwen2.5:3b"})
_MISSED_BAR = frozenset({"llama3.2", "gemma3:4b"})

STANDING_NOTES: dict[str, str] = {
    "missed_bar": "This model missed the published triage quality bar, so expect more wrong advice.",
    "not_measured": "This model has not been measured against the published triage quality bar.",
}


def triage_model_standing(model: str) -> TriageModelStanding:
    for prefix in _LOCAL_PREFIXES:
        if model.startswith(prefix):
            name = model.removeprefix(prefix).removesuffix(":latest")
            if name in _MET_BAR:
                return "met_bar"
            if name in _MISSED_BAR:
                return "missed_bar"
    return "not_measured"
