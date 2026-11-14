"""Tool capability classification runs once per tool on every current-graph build.

A 1,000-agent estate classifies about 27,000 tools while the build holds the
graph; the per-pattern Python scan made that the largest single cost of a cold
graph read. The result must stay identical to the token-prefix rule.
"""

from __future__ import annotations

import random
import re
import time

from agent_bom.risk_analyzer import CAPABILITY_PATTERNS, ToolCapability, _classify_cached, _token_capabilities, _tokenize, classify_tool


def _reference(tool_name: str, description: str = "") -> list[ToolCapability]:
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", tool_name + " " + description)
    tokens = {t.lower() for t in re.split(r"[^a-zA-Z0-9]+", spaced) if t}
    caps = {cap for cap, patterns in CAPABILITY_PATTERNS.items() if any(t.startswith(p) for p in patterns for t in tokens)}
    return sorted(caps, key=lambda c: c.value)


def _corpus(count: int, *, distinct: int) -> list[tuple[str, str]]:
    rng = random.Random(2145)
    words = sorted({p for patterns in CAPABILITY_PATTERNS.values() for p in patterns} | {"preset", "config", "widget", "Reader", "list"})
    names = []
    for index in range(distinct):
        picked = rng.sample(words, 3)
        name = f"{picked[0]}_{picked[1].capitalize()}{index}"
        description = f"Server {index} tool that will {picked[2]} records and returns the result to the calling agent"
        names.append((name, description))
    return [names[i % distinct] for i in range(count)]


def test_classification_matches_token_prefix_rule() -> None:
    for name, description in _corpus(3000, distinct=3000) + [("preset_config", ""), ("readFile", ""), ("MyAdminTool", ""), ("", "")]:
        assert classify_tool(name, description) == _reference(name, description), (name, description)


def test_returned_list_is_not_shared_between_calls() -> None:
    first = classify_tool("execute_shell", "run commands")
    first.clear()
    assert classify_tool("execute_shell", "run commands")


def _cold_caches() -> None:
    _classify_cached.cache_clear()
    _token_capabilities.cache_clear()


def _distinct_tokens(corpus: list[tuple[str, str]]) -> int:
    return len({token for name, description in corpus for token in _tokenize(name + " " + description)})


# These budgets count work, not wall time: a shared CI runner can stall any
# process for a second, but it cannot make a cache miss twice. Each keeps a
# generous wall-clock backstop that only a real regression would hit.


def test_estate_scale_classification_stays_within_budget() -> None:
    # 27,000 classifications over 600 distinct tools, the shape of a 1,000-agent
    # estate: each distinct tool is classified once and every repeat is a cache hit.
    corpus = _corpus(27_000, distinct=600)
    _cold_caches()
    started = time.perf_counter()
    for name, description in corpus:
        classify_tool(name, description)
    assert _classify_cached.cache_info().misses == 600
    assert _token_capabilities.cache_info().misses <= _distinct_tokens(corpus)
    assert time.perf_counter() - started < 5


def test_distinct_tools_classify_within_budget() -> None:
    corpus = _corpus(6000, distinct=6000)
    _cold_caches()
    started = time.perf_counter()
    for name, description in corpus:
        classify_tool(name, description)
    assert _classify_cached.cache_info().misses == 6000
    assert _token_capabilities.cache_info().misses <= _distinct_tokens(corpus)
    assert time.perf_counter() - started < 5


def test_unique_names_from_repeated_words_classify_within_budget() -> None:
    # Estate tool names are unique per server ("server-4821-tool-03") but built
    # from a few repeated words; at 5,000 agents that is about 130,000
    # classifications of distinct names. Token work is bounded by distinct tokens.
    corpus = [(f"mcp-server-{server}-tool-{tool:02d}", "") for server in range(13_000) for tool in range(10)]
    _cold_caches()
    started = time.perf_counter()
    for name, description in corpus:
        classify_tool(name, description)
    assert _token_capabilities.cache_info().misses <= _distinct_tokens(corpus)
    assert time.perf_counter() - started < 15
