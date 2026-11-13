"""Every Cytoscape style in the HTML report is one the pinned Cytoscape accepts.

Cytoscape drops a style property it cannot parse and logs a warning, so an
invalid value silently renders as the default. The static contract below runs
everywhere; the browser test loads a real report in Chromium and asserts that
Cytoscape logs no style warning. CI (``html-report-browser``) serves the
report's pinned scripts from the same versions' npm tarballs and requires the
browser test to run.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_bom.output.html import to_html
from agent_bom.output.html.graph_js_attack_flow import ATTACK_FLOW_GRAPH_JS
from agent_bom.output.html.graph_js_supply_chain import SUPPLY_CHAIN_GRAPH_JS, SUPPLY_CHAIN_SIDEBAR_JS
from agent_bom.output.html.graph_js_supply_chain_tools import SUPPLY_CHAIN_TOOLS_JS
from agent_bom.output.html.graph_js_view import GRAPH_VIEW_JS
from agent_bom.output.html.scripts import _EXTERNAL_SCRIPT_TAGS
from tests.html_report_scale_fixtures import scale_report

_REPO = Path(__file__).resolve().parents[1]
_SCRIPTS = {
    "attack_flow": ATTACK_FLOW_GRAPH_JS,
    "supply_chain": SUPPLY_CHAIN_GRAPH_JS,
    "supply_chain_sidebar": SUPPLY_CHAIN_SIDEBAR_JS,
    "supply_chain_tools": SUPPLY_CHAIN_TOOLS_JS,
    "view": GRAPH_VIEW_JS,
}

# Cytoscape 3.30.2 ``styfn.types.fontWeight.enums``: the string '700' is absent.
_FONT_WEIGHTS = {"normal", "bold", "bolder", "lighter", "100", "200", "300", "400", "500", "600", "800", "900"}
# Cytoscape 3.30.2 colour parser: names, #rgb, #rrggbb, rgb[a](), hsl[a](). Eight-digit hex is refused.
_COLOR = re.compile(r"^(#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}|[a-z]+|rgba?\(.*\)|hsla?\(.*\))$")
_COLOR_PROPS = re.compile(r"'((?:[a-z-]+-)?color)':\s*'([^']*)'")
_FONT_WEIGHT = re.compile(r"'font-weight':\s*(?:'([^']*)'|(\d+))")
_PINNED_SPEC = re.compile(r"https://[^/]+/(?:npm/)?([a-z.-]+@[0-9.]+)/")


@pytest.mark.parametrize("name", sorted(_SCRIPTS))
def test_font_weights_are_values_cytoscape_parses(name):
    for quoted, number in _FONT_WEIGHT.findall(_SCRIPTS[name]):
        if quoted:
            assert quoted in _FONT_WEIGHTS, f"{name}: font-weight '{quoted}' is refused by Cytoscape; use a number"
        else:
            assert int(number) in range(100, 1000, 100)


@pytest.mark.parametrize("name", sorted(_SCRIPTS))
def test_style_colors_are_values_cytoscape_parses(name):
    for prop, value in _COLOR_PROPS.findall(_SCRIPTS[name]):
        if value.startswith("data("):
            continue
        assert _COLOR.match(value), f"{name}: {prop}: {value} is refused by Cytoscape; use a colour plus an opacity"


@pytest.mark.parametrize("name", sorted(_SCRIPTS))
def test_no_custom_wheel_sensitivity(name):
    # Cytoscape logs a warning on every graph it builds with a non-default wheelSensitivity.
    assert "wheelSensitivity" not in _SCRIPTS[name]


def test_print_button_uses_no_emoji_glyph():
    report, blast = scale_report(2)
    page = to_html(report, blast)
    button = re.search(r'<button class="print-btn"[^>]*>(.*?)</button>', page, re.S)
    assert button is not None
    assert "&#x1f5b6;" not in button.group(1) and "\U0001f5b6" not in button.group(1)
    assert "<svg" in button.group(1) and "Print / Export PDF" in button.group(1)


def test_ci_fetches_exactly_the_script_versions_the_report_loads():
    pinned = set()
    for tag in _EXTERNAL_SCRIPT_TAGS:
        match = _PINNED_SPEC.search(tag)
        assert match is not None, tag
        pinned.add(match.group(1))
    ci = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    fetch = re.search(r"for spec in ([^;]+); do", ci)
    assert fetch is not None
    assert set(fetch.group(1).split()) == pinned


def _node_modules() -> Path | None:
    candidates = [os.environ.get("AGENT_BOM_PLAYWRIGHT_NODE_MODULES"), str(_REPO / "ui" / "node_modules")]
    for candidate in candidates:
        if candidate and (Path(candidate) / "playwright" / "package.json").is_file():
            return Path(candidate)
    return None


def _account_home() -> str:
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError):
        return os.environ.get("HOME", "")


def _unavailable(reason: str) -> None:
    # CI sets AGENT_BOM_REQUIRE_REPORT_BROWSER so a missing browser fails instead of passing silently.
    if os.environ.get("AGENT_BOM_REQUIRE_REPORT_BROWSER") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


_BROWSER_SCRIPT = r"""
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const vendor = process.env.AGENT_BOM_REPORT_JS_DIR || '';
const served = [];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  if (vendor) {
    // Serve each pinned CDN script from the same version's npm tarball; nothing reaches a CDN.
    await page.route(/^https:\/\/(unpkg\.com|cdn\.jsdelivr\.net)\//, route => {
      const rel = new URL(route.request().url()).pathname.replace(/^\/npm\//, '/').replace(/^\//, '');
      // jsdelivr minifies on request; the npm tarball ships the unminified build of the same version.
      const file = [rel, rel.replace(/\.min\.js$/, '.js')].map(r => path.join(vendor, r)).find(f => fs.existsSync(f));
      if (!file) return route.abort();
      served.push(rel);
      return route.fulfill({status: 200, contentType: 'application/javascript', body: fs.readFileSync(file)});
    });
  }
  const messages = [];
  page.on('console', m => messages.push({type: m.type(), text: m.text()}));
  page.on('pageerror', e => messages.push({type: 'pageerror', text: e.message}));
  await page.goto('file://' + process.argv[2], {waitUntil: 'load'});
  const loaded = await page.evaluate(() => typeof window.cytoscape === 'function');
  let drawn = [];
  if (loaded) {
    await page.waitForFunction(
      () => ['cy', 'cyAttack'].every(id => document.querySelector('#' + id + ' canvas')),
      null, {timeout: 30000});
    drawn = await page.evaluate(() => ['cy', 'cyAttack'].filter(id => document.querySelector('#' + id + ' canvas')));
  }
  console.log(JSON.stringify({loaded, drawn, served, messages}));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
"""


def test_report_graphs_load_in_chromium_without_cytoscape_style_warnings(tmp_path):
    node = shutil.which("node")
    modules = _node_modules()
    if not node or modules is None:
        _unavailable("Node.js and Playwright (ui/node_modules or AGENT_BOM_PLAYWRIGHT_NODE_MODULES) are required")
    report, blast = scale_report(40)
    page = tmp_path / "report.html"
    page.write_text(to_html(report, blast), encoding="utf-8")
    script = tmp_path / "probe.cjs"
    script.write_text(_BROWSER_SCRIPT, encoding="utf-8")
    # The suite points HOME at a throwaway directory; Playwright finds its browsers under the account's home.
    env = {**os.environ, "NODE_PATH": str(modules), "HOME": _account_home()}
    try:
        result = subprocess.run([node, str(script), str(page)], capture_output=True, text=True, timeout=120, env=env, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail("Chromium did not finish loading the report")
    if result.returncode != 0 and "Executable doesn't exist" in result.stderr:
        _unavailable("Playwright's Chromium is not installed")
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    if not outcome["loaded"]:
        _unavailable("Cytoscape could not be loaded from AGENT_BOM_REPORT_JS_DIR or its CDN")
    if os.environ.get("AGENT_BOM_REPORT_JS_DIR"):
        assert len(outcome["served"]) == len(_EXTERNAL_SCRIPT_TAGS), outcome["served"]
    assert outcome["drawn"] == ["cy", "cyAttack"]
    style_warnings = [m["text"] for m in outcome["messages"] if "style property" in m["text"]]
    assert style_warnings == []
    assert [m["text"] for m in outcome["messages"] if "wheel sensitivity" in m["text"].lower()] == []
    errors = [m["text"] for m in outcome["messages"] if m["type"] in {"error", "pageerror"}]
    assert errors == []
