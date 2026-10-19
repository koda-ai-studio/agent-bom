"""Prevent new severity judgments outside the canonical kernel.

Existing numeric maps below represent score weights, CVSS scores, SLA days,
probabilities or risk percentages, not ordering. Pin their complete values so
this exemption cannot conceal another map in the same file.
"""

import ast
from collections import Counter
from pathlib import Path

# These are policy inputs, not interchangeable ranking tables.
NON_RANKING_MAPS = {
    "exec_score.py": (
        "[('compliance', 6.0), ('critical', 12.0), ('exposure', 5.0), ('high', 6.0), "
        "('kev', 8.0), ('low', 0.5), ('medium', 2.0), ('unrated', 1.0)]"
    ),
    "trust_score.py": "[('critical', 5.0), ('high', 4.0), ('low', 1.0), ('medium', 2.0)]",
    "parsers/prompt_scanner.py": "[('critical', 9.0), ('high', 7.5), ('low', 2.5), ('medium', 5.0)]",
    "core/sla.py": "[('critical', 7), ('high', 30), ('low', 180), ('medium', 90)]",
    "core/exploitability.py": "[('critical', 40), ('high', 30), ('low', 8), ('medium', 18), ('none', 0), ('unknown', 0)]",
    "graph/toxic_findings.py": "[('critical', 9.5), ('high', 7.5), ('info', 1.0), ('low', 3.0), ('medium', 5.0)]",
    "runtime/protection.py": "[('critical', 4.0), ('high', 2.5), ('info', 0.0), ('low', 0.3), ('medium', 1.0)]",
    "demo_estate/enterprise_risk.py": "[('critical', 0.55), ('high', 0.28), ('low', 0.02), ('medium', 0.09)]",
    "api/risk_campaigns.py": "[('critical', 9.0), ('high', 7.0), ('info', 0.5), ('low', 1.5), ('medium', 4.0)]",
    "domain/skill_findings.py": "[('critical', 9.0), ('high', 7.5), ('low', 2.5), ('medium', 5.0)]",
    "api/cloud_scan_results.py": "[('critical', 100), ('high', 80), ('low', 20), ('medium', 50)]",
    "api/overview_rollup.py": "[('critical', 9.0), ('high', 7.0), ('low', 1.5), ('medium', 4.0)]",
}


def numeric_severity_maps(source):
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Dict):
            continue
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError):
            continue
        keys = {str(key).lower() for key in value}
        if not {"critical", "high", "medium", "low"}.issubset(keys):
            continue
        if not all(type(v) in (int, float) for v in value.values()) or len(set(value.values())) <= 1:
            continue  # Histograms and styling are not rank maps.
        yield node.lineno, repr(sorted(value.items()))


def test_src_has_no_inline_severity_rank_maps():
    root = Path(__file__).resolve().parents[1] / "src" / "agent_bom"
    violations = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root).as_posix()
        if relative == "core/severity.py":
            continue
        permitted = Counter([NON_RANKING_MAPS[relative]]) if relative in NON_RANKING_MAPS else Counter()
        for line, signature in numeric_severity_maps(path.read_text()):
            if permitted[signature]:
                permitted[signature] -= 1
            else:
                violations.append(f"{relative}:{line}")
    assert not violations, "Use core.severity for ranking: " + ", ".join(violations)


def test_guard_detects_inline_and_uppercase_ranks():
    assert list(numeric_severity_maps('x = {"critical": 4, "high": 3, "medium": 2, "low": 1}'))
    assert list(numeric_severity_maps('x = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}'))
    assert not list(numeric_severity_maps('x = {"critical": 0, "high": 0, "medium": 0, "low": 0}'))


def test_ui_severity_map_matches_python():
    import re

    from agent_bom.core.severity import SEVERITY_RANK

    source = (Path(__file__).resolve().parents[1] / "ui/lib/severity.ts").read_text()
    block = re.search(r"export const SEVERITY_ORDER[^=]*= \{([^}]+)\}", source).group(1)
    assert {key: int(value) for key, value in re.findall(r"(\w+): (-?\d+)", block)} == SEVERITY_RANK
