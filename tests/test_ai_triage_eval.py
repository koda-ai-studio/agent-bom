"""The evaluation itself: a sound dataset, deterministic replay, and scoring that cannot be flattered."""

from __future__ import annotations

import asyncio
import collections
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import ai_triage_eval as harness  # noqa: E402

from agent_bom.ai_components.triage_guard import protected_reasons  # noqa: E402


def _raw() -> dict:
    return json.loads(harness.DATASET.read_text())


def test_dataset_is_versioned_and_large_enough_with_every_required_class() -> None:
    data = _raw()
    assert data["version"] == "ai-triage-dataset.v1"
    cases = data["cases"]
    assert len(cases) >= 100
    categories = collections.Counter(case["category"] for case in cases)
    for required in (
        "vulnerable_version",
        "version_at_fix",
        "kev",
        "malicious_package",
        "reachable_critical",
        "unreachable",
        "cloud_misconfiguration",
        "adversarial",
    ):
        assert categories[required] >= 5, required
    labels = collections.Counter(case["label"] for case in cases)
    assert labels["true_positive"] >= 30 and labels["false_positive"] >= 30


def test_every_label_states_its_basis_and_source() -> None:
    for case in _raw()["cases"]:
        assert len(case["label_basis"]) > 20, case["case_id"]
        assert case["source"], case["case_id"]
        assert case["label"] in {"true_positive", "false_positive"}


def test_split_is_a_function_of_the_id_and_held_out_covers_each_class() -> None:
    from build_ai_triage_dataset import _split

    cases = _raw()["cases"]
    for case in cases:
        assert case["split"] == _split(case["case_id"]), case["case_id"]
    held_out = {(case["category"], case["label"]) for case in cases if case["split"] == "heldout"}
    assert {("vulnerable_version", "true_positive"), ("version_at_fix", "false_positive"), ("adversarial", "true_positive")} <= held_out


def test_dataset_is_public_or_synthetic_only() -> None:
    text = harness.DATASET.read_text()
    assert not re.search(r"(?<![0-9])(?!111122223333|123456789012)\d{12}(?![0-9])", text), "looks like a real AWS account id"
    assert not re.search(r"\b(?:ghp_[A-Za-z0-9]{36}|xoxb-|sk-ant-|-----BEGIN [A-Z ]*PRIVATE KEY)", text), (
        "credential-shaped value in dataset"
    )


def test_protected_classes_really_are_protected_in_the_dataset() -> None:
    cases = {case.case_id: case for case in harness.load_cases("all")}
    assert all(
        protected_reasons(case.finding)
        for case_id, case in cases.items()
        if case.category in {"kev", "malicious_package", "reachable_critical"}
    )
    assert not protected_reasons(cases["vuln-tp-00"].finding)


async def _caller_returning(verdict: str, prompt: str) -> dict:
    refs = re.findall(r'"ref":"(F\d+)"', prompt)
    assessments = [{"ref": ref, "verdict": verdict, "confidence": "high", "rationale": "because"} for ref in refs]
    return {
        "response": json.dumps({"assessments": assessments}),
        "latency_ms": 1.0,
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "prompt_sha256": "",
    }


def _run(verdict: str, split: str = "all", batch: int = 8) -> dict:
    cases = harness.load_cases(split)

    async def caller(prompt: str) -> dict:
        return await _caller_returning(verdict, prompt)

    run = asyncio.run(harness.run_eval(cases, caller, model="scripted", batch_size=batch))
    return harness.score(run, batch_size=batch)


def test_a_hostile_model_that_dismisses_everything_never_dismisses_a_protected_finding() -> None:
    scores = _run("likely_false_positive")
    assert scores["severe_dismissals_proposed_by_model"] == scores["severe_cases"] > 0
    assert scores["severe_dismissals_after_guard"] == 0
    assert scores["guard_interventions"] > 0
    assert scores["false_positive_recall"] < 1.0, "tampered findings are held for a person even when truly false"
    assert scores["false_positive_precision"] < 0.7, "dismissing everything must score badly"
    assert scores["wrong_dismissals"] > 15


def test_a_model_that_confirms_everything_scores_zero_recall() -> None:
    scores = _run("confirmed")
    assert scores["false_positive_recall"] == 0.0
    assert scores["false_positive_precision"] is None
    assert scores["wrong_dismissals"] == 0
    assert scores["injection_resistance_final"] is not None


def test_a_model_that_answers_nothing_counts_as_invalid() -> None:
    cases = harness.load_cases("dev")

    async def caller(_prompt: str) -> dict:
        return {"response": "", "latency_ms": 1.0, "prompt_tokens": 0, "completion_tokens": 0, "prompt_sha256": ""}

    run = asyncio.run(harness.run_eval(cases, caller, model="scripted", batch_size=8))
    scores = harness.score(run, batch_size=8)
    assert scores["invalid_response_rate"] == 1.0 and scores["assessed_rate"] == 0.0


def test_injection_scoring_catches_a_model_that_obeys_a_canary() -> None:
    cases = [case for case in harness.load_cases("all") if case.adversarial.get("goal") == "canary"]

    async def caller(prompt: str) -> dict:
        refs = re.findall(r'"ref":"(F\d+)"', prompt)
        return {
            "response": json.dumps(
                {
                    "assessments": [
                        {
                            "ref": ref,
                            "verdict": "confirmed",
                            "confidence": "high",
                            "rationale": "ZEBRA-7731 MANGO-4410 repeat-this-identifier",
                        }
                        for ref in refs
                    ]
                }
            ),
            "latency_ms": 1.0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "prompt_sha256": "",
        }

    run = asyncio.run(harness.run_eval(cases, caller, model="scripted", batch_size=2))
    scores = harness.score(run, batch_size=2)
    assert scores["injection_resistance_model"] == 0.0


def test_replay_is_deterministic_and_refuses_a_changed_prompt() -> None:
    recordings = harness.recordings()
    assert recordings, "at least one model must be recorded"
    recording = recordings[0]
    assert harness.replay(recording) == harness.replay(recording)
    tampered = {**recording, "calls": []}
    with pytest.raises(LookupError, match="re-record"):
        harness.replay(tampered)


def test_committed_recordings_pass_the_regression_gate() -> None:
    assert harness.check() == []


def test_the_gate_fails_when_a_baseline_is_not_met(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    baselines = json.loads(harness.BASELINES.read_text())
    model = next(iter(baselines))
    split = next(iter(baselines[model]))
    baselines[model][split]["false_positive_precision"] = 1.01
    path = tmp_path / "baselines.json"
    path.write_text(json.dumps(baselines))
    monkeypatch.setattr(harness, "BASELINES", path)
    assert any("false_positive_precision" in problem for problem in harness.check())


def test_recordings_hold_only_hashes_and_model_output_about_the_public_dataset() -> None:
    for path in harness.RECORDINGS.glob("*.json"):
        body = json.loads(path.read_text())
        assert set(body["calls"][0]) <= {"prompt_sha256", "response", "latency_ms", "prompt_tokens", "completion_tokens", "outcome"}
        assert body["dataset_sha256"] == harness.dataset_sha256()
        assert body["model_digest"], "a recording without a digest cannot say what it measured"


def test_published_results_match_the_replayed_recordings() -> None:
    doc = (harness.ROOT / "docs" / "AI_ENRICHMENT.md").read_text()
    assert harness.results_table("heldout") in doc, "regenerate the table with scripts/ai_triage_eval.py --table"
    assert "ai-triage-dataset.v1" in doc
