"""JS/TS framework labels name the packages that actually exist on npm."""

from __future__ import annotations

from agent_bom.ast.js_ts.facade import _frameworks_from_js_modules
from agent_bom.ast.js_ts.framework_imports import FRAMEWORK_HINTS


def test_vercel_ai_sdk_is_detected_from_its_real_package_names() -> None:
    assert _frameworks_from_js_modules({"ai"}) == ["Vercel AI SDK"]
    assert _frameworks_from_js_modules({"ai/rsc"}) == ["Vercel AI SDK"]
    assert _frameworks_from_js_modules({"@ai-sdk/openai", "@ai-sdk/anthropic"}) == ["Vercel AI SDK"]


def test_nonexistent_vercel_scope_is_not_a_hint() -> None:
    # registry.npmjs.org returns "Not found" for @vercel/ai; the SDK ships as `ai` and `@ai-sdk/*`.
    assert "@vercel/ai" not in FRAMEWORK_HINTS
    assert _frameworks_from_js_modules({"@vercel/analytics", "aiohttp-like", "main"}) == []
