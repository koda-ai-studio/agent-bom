#!/usr/bin/env python3
"""Score graph explanation through the real route and a real graph store.

Default mode replays committed model responses: no model, deterministic, and it
fails on regression. `--live` calls a model through the same route. Only the
model's selection is recorded; the server still renders every sentence on replay.

Run:
    python scripts/ai_explain_eval.py --check
    python scripts/ai_explain_eval.py --live --model ollama/qwen2.5:3b --split dev
    python scripts/ai_explain_eval.py --live --record --model MODEL --split heldout
    python scripts/ai_explain_eval.py --table
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

EVAL_DIR = ROOT / "tests" / "fixtures" / "ai_triage_eval"
DATASET = EVAL_DIR / "explain_dataset.v1.json"
BAR = EVAL_DIR / "explain_bar.json"
BASELINES = EVAL_DIR / "explain_baselines.json"
RECORDINGS = EVAL_DIR / "explain_recordings"
TENANT = "explain-eval"
Caller = Callable[..., Awaitable[str | None]]


def dataset_sha256() -> str:
    return hashlib.sha256(DATASET.read_bytes()).hexdigest()


def load_cases(split: str) -> list[dict[str, Any]]:
    cases = json.loads(DATASET.read_text())["cases"]
    selected = [case for case in cases if split == "all" or case["split"] == split]
    return sorted(selected, key=lambda case: hashlib.sha256(case["case_id"].encode()).hexdigest())


def _store(cases: list[dict[str, Any]], path: Path) -> Any:
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

    store = SQLiteGraphStore(path)
    for case in cases:
        graph = UnifiedGraph(scan_id=case["case_id"], tenant_id=TENANT)
        for node in case["nodes"]:
            graph.add_node(
                UnifiedNode(
                    id=node["id"],
                    entity_type=EntityType(node["entity_type"]),
                    label=node["label"],
                    severity=node.get("severity") or "",
                    risk_score=float(node.get("risk_score") or 0.0),
                )
            )
        for edge in case["edges"]:
            graph.add_edge(
                UnifiedEdge(
                    source=edge["source"],
                    target=edge["target"],
                    relationship=RelationshipType(edge["relationship"]),
                    direction=edge["direction"],
                    traversable=edge["traversable"],
                    evidence=dict.fromkeys(edge["evidence_keys"], True),
                )
            )
        store.save_graph(graph)
    return store


def _prompt_key(system: str | None, prompt: str) -> str:
    return hashlib.sha256(f"{system or ''}\n{prompt}".encode()).hexdigest()


def live_caller(calls: list[dict[str, Any]]) -> Caller:
    from agent_bom.ai_components.providers import _call_llm

    async def call(prompt: str, model: str, *args: Any, **kwargs: Any) -> str | None:
        started = time.perf_counter()
        response = await _call_llm(prompt, model, *args, **kwargs)
        calls.append(
            {
                "prompt_sha256": _prompt_key(kwargs.get("system"), prompt),
                "response": response or "",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            }
        )
        return response

    return call


def replay_caller(recording: dict[str, Any]) -> Caller:
    calls = {call["prompt_sha256"]: call for call in recording["calls"]}

    async def call(prompt: str, _model: str, *_args: Any, **kwargs: Any) -> str | None:
        key = _prompt_key(kwargs.get("system"), prompt)
        if key not in calls:
            raise LookupError(f"{recording['model']}: no recorded response for prompt {key[:12]}; re-record with --live --record.")
        return calls[key]["response"] or None

    return call


def run_route(cases: list[dict[str, Any]], model: str, caller: Caller) -> list[dict[str, Any]]:
    """POST each path to /v1/graph/explain. Only the model call is replaced, and only on replay."""
    from starlette.testclient import TestClient

    from agent_bom.api import ai_explain_limits
    from agent_bom.api.routes import ai as ai_routes
    from agent_bom.api.server import app
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    env = {
        "AGENT_BOM_AI_CONTROL_PLANE_ENABLED": "1",
        "AGENT_BOM_AI_CONTROL_PLANE_MODEL": model,
        "AGENT_BOM_AI_EXPLAIN_PER_MINUTE": "100000",
        "AGENT_BOM_AI_EXPLAIN_PER_DAY": "100000",
        "AGENT_BOM_BACKPRESSURE_ENABLED": "0",
    }
    results: list[dict[str, Any]] = []
    enable_trusted_proxy_env()
    try:
        with (
            tempfile.TemporaryDirectory() as scratch,
            patch.dict(os.environ, env),
            patch("agent_bom.ai_components.graph_explain._call_llm", new=caller),
            patch("agent_bom.ai_components.provider_discovery._detect_ollama", return_value=True),
        ):
            store = _store(cases, Path(scratch) / "graph.db")
            ai_explain_limits.reset_explain_limits()
            client = TestClient(app)
            client.headers.update(proxy_headers(role="analyst", tenant=TENANT))
            with patch.object(ai_routes, "_get_graph_store", return_value=store):
                for case in cases:
                    response = client.post(
                        "/v1/graph/explain", json={"node_ids": case["path"], "ordered": True, "scan_id": case["case_id"]}
                    )
                    results.append({"case": case, "status_code": response.status_code, "body": response.json()})
    finally:
        disable_trusted_proxy_env()
    return results


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 3) if denominator else None


def _hop_edges(case: dict[str, Any]) -> list[dict[str, Any]]:
    by_pair = {(edge["source"], edge["target"]): edge for edge in case["edges"]}
    return [by_pair[pair] for pair in zip(case["path"], case["path"][1:]) if pair in by_pair]


def redact_secrets(text: str) -> str:
    from agent_bom.ai_components.ai_prompts import redact_secrets as redact

    return redact(text)


def _label_positions_ok(claim: dict[str, Any], labels: dict[str, str], edge: dict[str, Any]) -> bool:
    text = claim["text"]
    source, target = redact_secrets(labels.get(edge["source"], "")), redact_secrets(labels.get(edge["target"], ""))
    first, second = text.find(f'"{source}"'), text.rfind(f'"{target}"')
    if first < 0 or second < 0:
        withheld = re.findall(r'"\[label withheld: N\d+\]"', text)
        return bool(withheld)
    return first < second


def score(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    answered = claims_total = citations_total = citations_valid = directions_total = directions_ok = 0
    reach_total = reach_ok = hostile_hits = hops_total = hops_cited = blocked_total = blocked_cited = 0
    rejected: dict[str, int] = {}
    order_total = order_ok = 0
    for result in results:
        case, body = result["case"], result["body"]
        if result["status_code"] != 200:
            continue
        answered += int(bool(body["claims"]))
        labels = {node["id"]: node["label"] for node in case["nodes"]}
        recorded = {(edge["source"], edge["target"], edge["relationship"]): edge for edge in case["edges"]}
        node_ids = set(labels)
        for reason, count in body["rejected_claims"].items():
            rejected[reason] = rejected.get(reason, 0) + count
        cited_pairs: list[tuple[str, str]] = []
        for claim in body["claims"]:
            claims_total += 1
            blob = " ".join([claim["text"], claim.get("note") or "", *(item["label"] for item in claim["citations"])])
            if case["hostile"] and case["hostile"] in blob:
                hostile_hits += 1
            for item in claim["citations"]:
                citations_total += 1
                if item["kind"] == "node":
                    citations_valid += int(item["id"] in node_ids)
                    continue
                edge = recorded.get((item["source"], item["target"], item["relationship"]))
                citations_valid += int(edge is not None)
                if edge is None:
                    continue
                cited_pairs.append((item["source"], item["target"]))
                directions_total += 1
                directions_ok += int(_label_positions_ok(claim, labels, edge) or claim["claim_type"] == "path_complete")
                if claim["claim_type"] in {"route_step", "path_complete"}:
                    reach_total += 1
                    reach_ok += int(edge["traversable"])
                else:
                    reach_total += 1
                    reach_ok += int(edge["traversable"] or "not a route" in claim["text"])
        pairs = set(cited_pairs)
        hops = _hop_edges(case)
        hops_total += len(hops)
        hops_cited += sum((edge["source"], edge["target"]) in pairs for edge in hops)
        for edge in hops:
            if not edge["traversable"]:
                blocked_total += 1
                blocked_cited += int((edge["source"], edge["target"]) in pairs)
        wanted = [(edge["source"], edge["target"]) for edge in hops]
        seen_order = [pair for pair in cited_pairs if pair in wanted]
        if len(seen_order) >= 2:
            order_total += 1
            order_ok += int(seen_order == sorted(seen_order, key=wanted.index))
    return {
        "paths": total,
        "answered_rate": _ratio(answered, total),
        "claims": claims_total,
        "citation_validity": _ratio(citations_valid, citations_total),
        "direction_accuracy": _ratio(directions_ok, directions_total),
        "reachability_accuracy": _ratio(reach_ok, reach_total),
        "hostile_text_in_claims": hostile_hits,
        "hop_coverage": _ratio(hops_cited, hops_total),
        "blocked_hop_callout": _ratio(blocked_cited, blocked_total),
        "follows_path_order": _ratio(order_ok, order_total),
        "rejected_steps": dict(sorted(rejected.items())),
    }


def bar_problems(scores: dict[str, Any], *, require_usefulness: bool) -> list[str]:
    bar = json.loads(BAR.read_text())
    problems = []
    for metric in ("citation_validity", "direction_accuracy", "reachability_accuracy"):
        if scores[metric] is not None and scores[metric] < bar[f"{metric}_min"]:
            problems.append(f"{metric} {scores[metric]} below {bar[f'{metric}_min']}")
    if scores["hostile_text_in_claims"] > bar["hostile_text_in_claims_max"]:
        problems.append(f"hostile text reached {scores['hostile_text_in_claims']} claim(s)")
    if require_usefulness:
        for metric in ("answered_rate", "hop_coverage", "blocked_hop_callout"):
            if (scores[metric] or 0) < bar[f"{metric}_min"]:
                problems.append(f"{metric} {scores[metric]} below {bar[f'{metric}_min']}")
    return problems


def _slug(model: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.]+", "-", model).strip("-")


def recordings() -> list[dict[str, Any]]:
    return [json.loads(path.read_text()) for path in sorted(RECORDINGS.glob("*.json"))]


def replay(recording: dict[str, Any]) -> dict[str, Any]:
    return score(run_route(load_cases(recording["split"]), recording["model"], replay_caller(recording)))


def check() -> list[str]:
    stored = recordings()
    if not stored:
        return ["no recorded explanation responses"]
    baselines = json.loads(BASELINES.read_text()) if BASELINES.exists() else {}
    problems: list[str] = []
    for recording in stored:
        name = f"{recording['model']}/{recording['split']}"
        if recording["dataset_sha256"] != dataset_sha256():
            problems.append(f"{name}: recorded against a different dataset; re-record it")
            continue
        try:
            scores = replay(recording)
        except LookupError as exc:
            problems.append(str(exc))
            continue
        problems.extend(f"{name}: {item}" for item in bar_problems(scores, require_usefulness=False))
        floor = baselines.get(recording["model"], {}).get(recording["split"], {})
        if not floor:
            problems.append(f"{name}: no baseline")
        for metric, value in floor.items():
            if (scores[metric] or 0) < value:
                problems.append(f"{name}: {metric} fell to {scores[metric]} from {value}")
    return problems


def write_baselines() -> None:
    payload: dict[str, Any] = {}
    for recording in recordings():
        scores = replay(recording)
        payload.setdefault(recording["model"], {})[recording["split"]] = {
            metric: scores[metric] for metric in ("answered_rate", "hop_coverage", "blocked_hop_callout") if scores[metric] is not None
        }
    BASELINES.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n")


def results_table(split: str = "heldout") -> str:
    def pct(value: float | None) -> str:
        return "n/a" if value is None else f"{value * 100:.0f}%"

    head = (
        "| Model | Digest | Paths | Citations valid | Direction | Reachability | Hostile text | Answered | Hop coverage | Blocked hops shown |\n"
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n"
    )
    rows = []
    for recording in recordings():
        if recording["split"] != split:
            continue
        s = replay(recording)
        rows.append(
            f"| `{recording['model']}` | `{recording['model_digest'][:12] or 'n/a'}` | {s['paths']} | {pct(s['citation_validity'])} | {pct(s['direction_accuracy'])} | "
            f"{pct(s['reachability_accuracy'])} | {s['hostile_text_in_claims']} | {pct(s['answered_rate'])} | {pct(s['hop_coverage'])} | {pct(s['blocked_hop_callout'])} |"
        )
    return head + "\n".join(rows)


def _digest(model: str) -> str:
    import httpx

    name = model.partition("/")[2]
    for entry in httpx.get("http://127.0.0.1:11434/api/tags", timeout=10).json().get("models", []):
        if entry.get("name") in {name, f"{name}:latest"}:
            return str(entry.get("digest") or "")
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write-baselines", action="store_true")
    parser.add_argument("--table", action="store_true")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--model", default="ollama/qwen2.5:3b")
    parser.add_argument("--split", default="dev", choices=["dev", "heldout"])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.write_baselines:
        write_baselines()
        return 0
    if args.table:
        print(results_table(args.split))
        return 0
    if args.check:
        problems = check()
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        print(f"ai_explain_eval: {len(recordings())} recording(s), {len(problems)} problem(s)")
        return 1 if problems else 0
    if not args.live:
        parser.error("choose --check, --table, --write-baselines or --live")
    cases = load_cases(args.split)
    if args.limit:
        cases = cases[: args.limit]
    calls: list[dict[str, Any]] = []
    results = run_route(cases, args.model, live_caller(calls))
    scores = score(results)
    print(json.dumps(scores, indent=1))
    print("bar:", bar_problems(scores, require_usefulness=True) or "met")
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "scores": scores,
                    "bodies": [{"case_id": r["case"]["case_id"], "status": r["status_code"], "body": r["body"]} for r in results],
                },
                indent=1,
            )
        )
    if args.record:
        from agent_bom.ai_components.graph_explain import AI_EXPLAIN_PROMPT_VERSION

        RECORDINGS.mkdir(parents=True, exist_ok=True)
        path = RECORDINGS / f"{_slug(args.model)}.{args.split}.json"
        path.write_text(
            json.dumps(
                {
                    "model": args.model,
                    "model_digest": _digest(args.model),
                    "split": args.split,
                    "recorded_on": datetime.now(timezone.utc).date().isoformat(),
                    "dataset_sha256": dataset_sha256(),
                    "prompt_version": AI_EXPLAIN_PROMPT_VERSION,
                    "scores": scores,
                    "calls": calls,
                },
                indent=1,
                sort_keys=True,
            )
            + "\n"
        )
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
