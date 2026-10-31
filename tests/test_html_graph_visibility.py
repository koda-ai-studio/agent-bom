"""Exported graphs must fit their first visible viewport without resetting later zoom."""

import json
import re
import shutil
import subprocess

import pytest


@pytest.mark.parametrize("graph_kind", ["supply", "attack"])
@pytest.mark.parametrize("user_moved", [False, True])
def test_hidden_graph_refits_on_resize_but_preserves_a_user_view(graph_kind: str, user_moved: bool) -> None:
    from agent_bom.output.html import scripts
    from agent_bom.output.html.graph_js_attack_flow import ATTACK_FLOW_GRAPH_JS
    from agent_bom.output.html.graph_js_supply_chain import SUPPLY_CHAIN_GRAPH_JS

    source = SUPPLY_CHAIN_GRAPH_JS if graph_kind == "supply" else ATTACK_FLOW_GRAPH_JS
    ready = re.search(r"\.ready\(function\(\) \{ (.*?) \}\);", source)
    assert ready is not None
    visibility = getattr(scripts, "GRAPH_VISIBILITY_JS", "")

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the exported graph lifecycle contract")
    script = (
        """
const callbacks = [];
global.ResizeObserver = class { constructor(callback) { callbacks.push(callback); } observe() {} };
global.window = { addEventListener() {} };
global.document = { addEventListener() {} };
const element = { clientWidth: 0, clientHeight: 0 };
const calls = { resize: 0, fit: 0 };
const events = [];
const graph = { on(name, callback) {events.push(callback);}, resize() { calls.resize++; },
elements() { return ['node']; }, fit(nodes, padding) {
  if (nodes[0] !== 'node' || padding !== 40) throw new Error('wrong graph scope');
  calls.fit++;
} };
const cy = graph, cyAtk = graph, cyContainer = element, cyAtkContainer = element;
"""
        + visibility
        + ready.group(1)
        + """
const hidden = {...calls};
element.clientWidth = 390; element.clientHeight = 500;
if (callbacks[0]) callbacks[0](); const revealed = {...calls};
"""
        + ("if (events[0]) events[0]();" if user_moved else "")
        + """
element.clientWidth = 0; if (callbacks[0]) callbacks[0](); const hiddenAgain = {...calls};
element.clientWidth = 1440; if (callbacks[0]) callbacks[0](); const reopened = {...calls};
console.log(JSON.stringify({hidden, revealed, hiddenAgain, reopened}));
"""
    )
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {
        "hidden": {"resize": 0, "fit": 0},
        "revealed": {"resize": 1, "fit": 1},
        "hiddenAgain": {"resize": 1, "fit": 1},
        "reopened": {"resize": 2, "fit": 1 if user_moved else 2},
    }


def test_print_expands_evidence_and_restores_each_disclosure() -> None:
    from agent_bom.output.html import scripts

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the exported report lifecycle contract")
    script = (
        """
const handlers = {};
global.window = {addEventListener(name, callback) {handlers[name] = callback;}};
const details = [{open:false}, {open:true}, {open:false}];
global.document = {querySelectorAll() {return details;}};
"""
        + getattr(scripts, "PRINT_DETAILS_JS", "")
        + """
handlers.beforeprint?.();
const printing = details.map(el => el.open);
handlers.beforeprint?.();
handlers.afterprint?.();
console.log(JSON.stringify({printing, restored:details.map(el => el.open)}));
"""
    )
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {"printing": [True, True, True], "restored": [False, True, False]}
