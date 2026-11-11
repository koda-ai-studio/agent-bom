"""The findings pager is usable from the keyboard: named buttons, announced position, focus kept on paging."""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from agent_bom.output.html.paginator_js import PAGINATOR_JS
from agent_bom.output.html.sections_findings import _pager_controls


def test_pager_buttons_are_named_and_the_position_is_announced():
    bar = _pager_controls("vulnTable", 1800)
    assert 'role="navigation"' in bar and 'aria-label="Vulnerability pages"' in bar
    buttons = re.findall(r"<button\b[^>]*>", bar)
    assert len(buttons) == 4
    for button in buttons:
        assert 'type="button"' in button
        assert re.search(r'aria-label="(First|Previous|Next|Last) page"', button), button
    assert '<span class="pager-info" aria-live="polite">' in bar
    assert '<select class="pager-size" aria-label="Rows per page">' in bar


@pytest.mark.parametrize(
    ("focused", "disabled", "expected"),
    [
        ("next", ["next", "last"], "prev"),
        ("last", ["next", "last"], "prev"),
        ("prev", ["first", "prev"], "next"),
        ("first", ["first", "prev"], "next"),
        ("next", [], "next"),
    ],
)
def test_focus_moves_to_a_live_button_when_paging_disables_the_focused_one(focused, disabled, expected):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the exported pager contract")
    script = (
        PAGINATOR_JS
        + f"""
const acts = ['first', 'prev', 'next', 'last'];
const disabled = {json.dumps(disabled)};
const buttons = acts.map(act => ({{
  act, disabled: disabled.includes(act),
  getAttribute(name) {{ return name === 'data-act' ? act : null; }},
  focus() {{ global.document.activeElement = this; }},
}}));
const bar = {{
  contains(el) {{ return buttons.includes(el); }},
  querySelector(sel) {{ return buttons.find(b => sel === '[data-act="' + b.act + '"]') || null; }},
}};
global.document = {{ activeElement: buttons[acts.indexOf({json.dumps(focused)})] }};
keepPagerFocus(bar);
console.log(JSON.stringify(document.activeElement.act));
"""
    )
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, check=True, timeout=60)
    assert json.loads(result.stdout) == expected
