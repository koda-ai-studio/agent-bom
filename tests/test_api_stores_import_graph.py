"""Default store registration does not initialize optional graph backends."""

import json
import subprocess
import sys


def test_api_stores_does_not_load_neptune_or_scanner_stack():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, sys, agent_bom.api.stores; "
            "print(json.dumps([name for name in ('agent_bom.api.neptune_graph', 'agent_bom.scanners.risk') if name in sys.modules]))",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout) == []
