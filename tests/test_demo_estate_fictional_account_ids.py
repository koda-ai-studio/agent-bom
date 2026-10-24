"""The public demo names only AWS account ids that cannot belong to anyone real.

AWS documentation reserves no account range, so the demo uses the ids its own
docs print as examples: the four IAM examples for hand-authored accounts and the
repeated-digit series from the Organizations guide for the generated population.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_bom.demo_estate.enterprise_composition import build_demo_estate

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom"
DOCUMENTED_EXAMPLES = frozenset({"123456789012", "111122223333", "444455556666", "777788889999"})
REPEATED_DIGIT_EXAMPLES = frozenset(str(digit) * 12 for digit in range(1, 10))
ALLOWED = DOCUMENTED_EXAMPLES | REPEATED_DIGIT_EXAMPLES
# A bare 12-digit run, not a slice of a UUID, hex digest or longer number.
_ACCOUNT_RE = re.compile(r"(?<![0-9A-Za-z-])(\d{12})(?![0-9A-Za-z-])")
DEMO_SOURCES = (
    *sorted((SRC / "demo_estate").rglob("*.py")),
    *sorted((SRC / "demo_estate" / "data").glob("*.jsonl")),
    SRC / "demo.py",
    SRC / "demo_advisories.py",
)


def test_demo_sources_name_only_documented_example_accounts():
    offenders = {
        f"{path.relative_to(SRC)}:{match}"
        for path in DEMO_SOURCES
        for match in _ACCOUNT_RE.findall(path.read_text())
        if match not in ALLOWED
    }
    assert not offenders, sorted(offenders)


def test_built_demo_estate_names_only_documented_example_accounts():
    estate = build_demo_estate(tenant_id="default")
    blob = json.dumps([asset.model_dump() for asset in estate.assets], default=str)

    found = set(_ACCOUNT_RE.findall(blob))
    aws_scopes = {asset.account_scope for asset in estate.assets if asset.provider == "aws"}

    assert found - ALLOWED == set()
    assert aws_scopes <= ALLOWED
    # Distinct accounts stay distinct: the population is not collapsed to fit.
    assert len(aws_scopes) == 9
