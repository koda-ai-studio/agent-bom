"""Dashboard labels must match the scanner vocabulary, including less common IDs."""

import json
from pathlib import Path

from agent_bom.atlas import ATLAS_TECHNIQUES


def test_dashboard_atlas_vocabulary_matches_scanner():
    source = (Path(__file__).resolve().parents[1] / "ui/lib/atlas-labels.generated.ts").read_text()
    labels = json.loads(source.split(" = ", 1)[1].removesuffix(";\n"))
    assert labels == ATLAS_TECHNIQUES
    assert labels["AML.T0037"] == "Data from Local System"
