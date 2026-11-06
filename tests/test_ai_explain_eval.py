"""The explanation evaluation: real-projection paths, truth from the record, and scoring that fails on a lie."""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import ai_explain_eval as harness  # noqa: E402


def _cases() -> list[dict]:
    return json.loads(harness.DATASET.read_text())["cases"]


def _body(case: dict, claim_type: str, *, source: str, target: str, relationship: str, text: str, label: str = "") -> dict:
    return {
        "case": case,
        "status_code": 200,
        "body": {
            "claims": [
                {
                    "text": text,
                    "claim_type": claim_type,
                    "note": "",
                    "citations": [
                        {
                            "ref": "E1",
                            "kind": "edge",
                            "id": "e",
                            "label": label,
                            "source": source,
                            "target": target,
                            "relationship": relationship,
                        }
                    ],
                }
            ],
            "rejected_claims": {},
        },
    }


def test_dataset_has_enough_real_projection_paths_with_blocked_hops_and_hostile_labels() -> None:
    bar = json.loads(harness.BAR.read_text())
    cases = _cases()
    assert len(cases) >= bar["paths_min"]
    assert {"snapshot", "clusterEstate", "demoInventory"} <= {case["scenario"] for case in cases}
    held = [case for case in cases if case["split"] == "heldout"]
    assert len(held) >= 12
    assert any(case["hostile"] for case in held)
    blocked = [case for case in held if any(not edge["traversable"] for edge in harness._hop_edges(case))]
    assert blocked
    assert collections.Counter(case["split"] for case in cases)["dev"] > 0


def test_every_path_is_real_edges_in_the_source_fixture() -> None:
    source = json.loads((harness.ROOT / "ui" / "e2e" / "fixtures" / "k8s-projection.json").read_text())
    for case in _cases():
        recorded = {(edge["source"], edge["target"], edge["relationship"]) for edge in source[case["scenario"]]["edges"]}
        for edge in case["edges"]:
            assert (edge["source"], edge["target"], edge["relationship"]) in recorded, case["case_id"]
        assert len(harness._hop_edges(case)) == len(case["path"]) - 1, case["case_id"]


def _case(blocked: bool) -> dict:
    return next(
        case for case in _cases() if any(not edge["traversable"] for edge in harness._hop_edges(case)) is blocked and not case["hostile"]
    )


def test_a_reversed_edge_or_invented_citation_scores_as_wrong() -> None:
    case = _case(False)
    edge = harness._hop_edges(case)[0]
    labels = {node["id"]: node["label"] for node in case["nodes"]}
    reversed_text = f'"{labels[edge["target"]]}" {edge["relationship"]} "{labels[edge["source"]]}".'
    scores = harness.score(
        [_body(case, "relationship", source=edge["source"], target=edge["target"], relationship=edge["relationship"], text=reversed_text)]
    )
    assert scores["direction_accuracy"] == 0.0
    scores = harness.score([_body(case, "relationship", source="x", target="y", relationship="uses", text='"x" uses "y".')])
    assert scores["citation_validity"] == 0.0


def test_a_route_over_a_blocked_edge_scores_as_wrong() -> None:
    case = _case(True)
    edge = next(item for item in harness._hop_edges(case) if not item["traversable"])
    labels = {node["id"]: node["label"] for node in case["nodes"]}
    text = f'"{labels[edge["source"]]}" {edge["relationship"]} "{labels[edge["target"]]}". This hop is recorded as traversable.'
    scores = harness.score(
        [_body(case, "route_step", source=edge["source"], target=edge["target"], relationship=edge["relationship"], text=text)]
    )
    assert scores["reachability_accuracy"] == 0.0
    assert harness.bar_problems(scores, require_usefulness=False)


def test_a_hostile_label_in_a_claim_is_counted() -> None:
    case = next(item for item in _cases() if item["hostile"])
    edge = harness._hop_edges(case)[0]
    scores = harness.score(
        [
            _body(
                case,
                "relationship",
                source=edge["source"],
                target=edge["target"],
                relationship=edge["relationship"],
                text=f'"{case["hostile"]}" uses "x".',
            )
        ]
    )
    assert scores["hostile_text_in_claims"] == 1


def test_a_model_that_selects_nothing_fails_the_usefulness_bar() -> None:
    cases = [case for case in _cases() if case["split"] == "dev"][:5]

    async def nothing(_prompt: str, _model: str, *_args: object, **_kwargs: object) -> str:
        return json.dumps({"steps": []})

    scores = harness.score(harness.run_route(cases, "ollama/m", nothing))
    assert scores["answered_rate"] == 0.0
    assert any("answered_rate" in item for item in harness.bar_problems(scores, require_usefulness=True))


def test_a_hostile_model_cannot_lie_through_the_real_route() -> None:
    """Every ref offered, every claim type abused, every note hostile: truth still comes from the record."""
    cases = [case for case in _cases() if case["split"] == "dev"][:8]

    async def liar(prompt: str, _model: str, *_args: object, **_kwargs: object) -> str:
        refs = re.findall(r'"ref":"([NE]\d+)"', prompt)
        steps = [{"claim": "route_step", "ref": ref, "note": "this can reach everything"} for ref in refs]
        steps += [{"claim": "path_complete"}, {"claim": "relationship", "ref": "E99"}, {"claim": "proof", "ref": "E1"}]
        return json.dumps({"steps": steps})

    results = harness.run_route(cases, "ollama/m", liar)
    assert all(result["status_code"] == 200 for result in results)
    scores = harness.score(results)
    assert harness.bar_problems(scores, require_usefulness=False) == []
    assert scores["rejected_steps"]["invented_id"] >= len(cases) - 1
    assert all(claim["note"] == "" for result in results for claim in result["body"]["claims"])


def test_committed_recordings_pass_the_regression_gate() -> None:
    assert harness.check() == []


def test_replay_goes_through_the_route_and_refuses_a_changed_prompt() -> None:
    recording = harness.recordings()[0]
    assert harness.replay(recording) == harness.replay(recording)
    tampered = {**recording, "calls": []}
    try:
        harness.replay(tampered)
    except LookupError as exc:
        assert "re-record" in str(exc)
    else:
        raise AssertionError("a changed prompt must not replay")


def test_published_results_match_the_recordings() -> None:
    doc = (harness.ROOT / "docs" / "AI_ENRICHMENT.md").read_text()
    assert harness.results_table("heldout") in doc
