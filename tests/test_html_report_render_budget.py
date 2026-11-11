"""The standalone HTML report mounts one page of rows per findings list and still carries every record.

Fixtures come from ``tests.html_report_scale_fixtures`` (2,000 findings: long
advisory text, repeated assets, mixed missing evidence). The 10,000 and 50,000
sizes are measured with ``python -m tests.html_report_scale_fixtures``.
"""

from __future__ import annotations

import html as html_lib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import pytest

from agent_bom.output import to_json
from agent_bom.output.html import _PAGE_SIZE, to_html
from tests.html_report_scale_fixtures import scale_report

_FINDINGS = 2000
# Ceilings sit about 2-3x above the values measured on an Apple M4, so slower CI
# runners pass while a regression in per-finding cost still fails.
_MAX_BYTES = 12_000_000
_MAX_CPU_S = 8.0
_MAX_PEAK_RSS_GROWTH_MIB = 400
_LISTS = ("vulnTable", "policyFindingsTable", "blastTable", "remediationList", "remediationNoFix")


@pytest.fixture(scope="module")
def rendered():
    report, radii = scale_report(_FINDINGS)
    started = time.process_time()
    document = to_html(report, radii)
    return report, document, time.process_time() - started


def _mounted(document: str, list_id: str) -> str:
    start = document.index(f'id="{list_id}"')
    if document.startswith("<table", document.rindex("<", 0, start)):
        body = document.index("<tbody>", start)
        return document[body : document.index("</tbody>", body)]
    segment = document[start : document.index(f'<div class="pager" data-pager="{list_id}"', start)]
    return segment.split('<script type="text/html"', 1)[0]


def _deferred(document: str, list_id: str) -> list[str]:
    pattern = rf'<script type="text/html" class="deferred-rows" data-rows-for="{list_id}">(.*?)</script>'
    blocks = re.findall(pattern, document, flags=re.DOTALL)
    return [row for block in blocks for row in block.split("\n") if row]


def _records(document: str, list_id: str) -> int:
    marker = {"remediationList": 'class="remediation-item"', "remediationNoFix": 'class="no-fix-item"'}.get(list_id, "<tr")
    return _mounted(document, list_id).count(marker) + sum(row.count(marker) for row in _deferred(document, list_id))


def test_each_findings_list_mounts_at_most_one_page(rendered):
    _, document, _ = rendered
    for list_id in _LISTS:
        mounted = _mounted(document, list_id)
        assert mounted.count("<tr") + mounted.count('class="remediation-item"') + mounted.count('class="no-fix-item"') <= _PAGE_SIZE, (
            list_id
        )
        assert f'data-pager="{list_id}"' in document, list_id


def test_offline_file_carries_every_record_exactly_once(rendered):
    report, document, _ = rendered
    canonical = to_json(report)["findings"]
    cve = [finding for finding in canonical if finding["finding_type"] == "CVE"]
    policy = [finding for finding in canonical if finding["finding_type"] != "CVE"]
    assert len(cve) + len(policy) == _FINDINGS

    vuln_rows = [_mounted(document, "vulnTable")] + _deferred(document, "vulnTable")
    ids = Counter(html_lib.unescape(found) for row in vuln_rows for found in re.findall(r'<code class="vuln-id">([^<]*)</code>', row))
    assert ids == Counter(finding["cve_id"] for finding in cve)
    assert _records(document, "policyFindingsTable") == len(policy)
    assert _records(document, "blastTable") == len(cve)
    with_fix = sum(1 for finding in cve if finding["fixed_version"])
    assert _records(document, "remediationList") == with_fix
    assert _records(document, "remediationNoFix") == len(cve) - with_fix
    # Counts shown to the reader are the whole set, not the mounted page.
    assert f"1&ndash;{_PAGE_SIZE} of {len(cve)}</span>" in document
    assert f"of {len(policy)}</span>" in document


def test_deferred_rows_are_inert_text_with_escaped_evidence(rendered):
    _, document, _ = rendered
    assert "<script>x</script>" not in document
    for list_id in _LISTS:
        for row in _deferred(document, list_id):
            assert "</script" not in row.lower() and "<!--" not in row
            assert "\n" not in row
    deferred = _deferred(document, "vulnTable")
    assert all('class="finding-evidence"' in row for row in deferred)
    assert sum("&lt;script&gt;x&lt;/script&gt;" in row for row in deferred) > len(deferred) // 2
    assert "<noscript>" in document


def test_export_stays_within_cpu_and_size_budget(rendered):
    _, document, cpu = rendered
    size = len(document.encode())
    assert size < _MAX_BYTES, f"{size:,} bytes for {_FINDINGS:,} findings"
    assert cpu < _MAX_CPU_S, f"{cpu:.2f}s CPU for {_FINDINGS:,} findings"


def test_export_peak_memory_stays_within_budget():
    # A fresh process: peak RSS only grows, and allocation tracing would distort the export it measures.
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(root / "src"), str(root)])}
    completed = subprocess.run(
        [sys.executable, "-m", "tests.html_report_scale_fixtures", "--one", str(_FINDINGS)],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    measured = json.loads(completed.stdout.strip().splitlines()[-1])
    assert measured["findings"] == _FINDINGS
    growth = measured["peak_rss_growth_mib"]
    assert growth < _MAX_PEAK_RSS_GROWTH_MIB, f"{growth} MiB peak RSS growth exporting {_FINDINGS:,} findings"


def test_small_report_has_no_deferred_rows():
    report, radii = scale_report(20)
    document = to_html(report, radii)
    assert 'class="deferred-rows"' not in document
    assert "<noscript>" not in document
