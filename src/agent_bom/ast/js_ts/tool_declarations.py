"""Read tool declarations from masked JS/TS source without executing it."""

from __future__ import annotations

import re

from agent_bom.ast_signal_utils import _balanced_segment

_JS_STRING_ARG_RE = re.compile(r"""\s*(?P<quote>["'`])(?P<name>[^"'`]*)(?P=quote)""")


# Servers built on the low-level ``Server`` class rather than the ``McpServer``
# wrapper declare their tools in the ListTools response. The v1 SDK passes the
# schema object and the v2 SDK the method string -- the SDK's own v1->v2 codemod
# rewrites ``ListToolsRequestSchema`` to ``'tools/list'`` -- so both are matched.
_JS_SET_REQUEST_HANDLER_START_RE = re.compile(r"""\bsetRequestHandler\s*\(""")


_JS_LIST_TOOLS_SELECTOR_RE = re.compile(r"""\(\s*(?:ListToolsRequestSchema\b|(?P<quote>["'`])tools/list(?P=quote))""")


_JS_TOOLS_ARRAY_START_RE = re.compile(r"""\btools\s*:\s*\[""")


_JS_NAME_KEY_RE = re.compile(r"""\bname\s*:""")


# The Vercel AI SDK and Mastra pass a tools MAP whose KEY is the tool name:
#   tools: { weather: tool({ description, inputSchema, execute }) }
# Requiring ``{``, ``,`` or a newline before the key keeps ``cond ? a : tool(x)``
# and ``case foo: tool()`` from being read as a registration.
_JS_OBJECT_KEY_BEFORE_RE = re.compile(r"""[{,\n]\s*(?P<key>[A-Za-z_$][\w$]*)\s*:\s*$""")


_JS_OBJECT_KEY_LOOKBEHIND = 120


def _js_first_string_argument(source: str, open_paren_index: int) -> str:
    """Return the leading string-literal argument of the call at ``open_paren_index``."""
    if open_paren_index < 0 or open_paren_index >= len(source) or source[open_paren_index] != "(":
        return ""
    match = _JS_STRING_ARG_RE.match(source, open_paren_index + 1)
    return match.group("name").strip() if match else ""


def _js_bracket_depths(masked: str) -> list[int]:
    """Return the bracket depth at every offset of *masked*.

    An opening bracket reports the depth it opens and a closing bracket the
    depth it closes, so the contents of a literal that starts at offset 0 all
    read as depth 1. Only comment/string-masked text may be passed: a bracket
    inside a string literal would otherwise skew every following depth.
    """
    depths: list[int] = []
    depth = 0
    for char in masked:
        if char in "{[(":
            depth += 1
            depths.append(depth)
        elif char in "}])":
            depths.append(depth)
            depth -= 1
        else:
            depths.append(depth)
    return depths


def _js_name_property_at_depth_one(masked_literal: str, source_literal: str) -> str:
    """Return the ``name: "…"`` value declared directly on a masked object literal."""
    depths = _js_bracket_depths(masked_literal)
    for key_match in _JS_NAME_KEY_RE.finditer(masked_literal):
        if depths[key_match.start()] != 1:
            continue
        value_match = _JS_STRING_ARG_RE.match(source_literal, key_match.end())
        return value_match.group("name").strip() if value_match else ""
    return ""


def _js_object_literals_at_depth(masked: str, source: str, *, depth: int) -> list[tuple[int, str, str]]:
    """Return ``(offset, masked, real)`` for each ``{…}`` opening at *depth* in *masked*."""
    literals: list[tuple[int, str, str]] = []
    depths = _js_bracket_depths(masked)
    index = 0
    while index < len(masked):
        if masked[index] != "{" or depths[index] != depth:
            index += 1
            continue
        segment = _balanced_segment(masked, index, open_char="{", close_char="}")
        if segment is None:
            break
        masked_literal, end = segment
        literals.append((index, masked_literal, source[index : index + len(masked_literal)]))
        index = end
    return literals


def _js_named_option_argument(source: str, masked_source: str, open_paren_index: int) -> str:
    """Return a ``name:`` declared on an options object passed to a tool call.

    LangChain JS puts the name there rather than in a leading string argument:
    ``tool(fn, { name: 'search_database', description, schema })``.
    """
    segment = _balanced_segment(masked_source, open_paren_index, open_char="(", close_char=")")
    if segment is None:
        return ""
    masked_args, _ = segment
    source_args = source[open_paren_index : open_paren_index + len(masked_args)]
    for _offset, masked_literal, source_literal in _js_object_literals_at_depth(masked_args, source_args, depth=2):
        name = _js_name_property_at_depth_one(masked_literal, source_literal)
        if name:
            return name
    return ""


def _js_object_key_before(masked_source: str, index: int) -> str:
    """Return the object key a tool call is assigned to, as in ``{ weather: tool(…) }``."""
    window = masked_source[max(0, index - _JS_OBJECT_KEY_LOOKBEHIND) : index]
    match = _JS_OBJECT_KEY_BEFORE_RE.search(window)
    return match.group("key") if match else ""


def _js_low_level_tool_declarations(source: str, masked_source: str) -> list[tuple[str, int]]:
    """Return ``(tool_name, line_number)`` declared by low-level ListTools handlers."""
    declarations: list[tuple[str, int]] = []
    for match in _JS_SET_REQUEST_HANDLER_START_RE.finditer(masked_source):
        open_index = match.end() - 1
        # The schema identifier survives masking; the ``'tools/list'`` method
        # string does not, so the selector is read from the real source.
        if _JS_LIST_TOOLS_SELECTOR_RE.match(source, open_index) is None:
            continue
        call_segment = _balanced_segment(masked_source, open_index, open_char="(", close_char=")")
        if call_segment is None:
            continue
        masked_call, _ = call_segment
        array_match = _JS_TOOLS_ARRAY_START_RE.search(masked_call)
        if array_match is None:
            continue
        array_index = open_index + array_match.end() - 1
        array_segment = _balanced_segment(masked_source, array_index, open_char="[", close_char="]")
        if array_segment is None:
            continue
        masked_array, _ = array_segment
        source_array = source[array_index : array_index + len(masked_array)]
        for offset, masked_literal, source_literal in _js_object_literals_at_depth(masked_array, source_array, depth=2):
            name = _js_name_property_at_depth_one(masked_literal, source_literal)
            if not name:
                continue
            declarations.append((name, source[: array_index + offset].count("\n") + 1))
    return declarations
