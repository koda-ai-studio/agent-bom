"""The runtime reconnect proof's chart values must render against the current chart."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/demo/check_runtime_reconnect.py"


def _script():
    spec = importlib.util.spec_from_file_location("abom_runtime_reconnect_proof", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pool_sizes_are_chart_values_and_attestation_comes_from_the_auth_secret() -> None:
    values = _script().helm_values("agent-bom:local", shared_delivery=False)
    api = values["controlPlane"]["api"]
    assert values["controlPlane"]["postgres"]["pool"] == {"minSize": 1, "maxSize": 2}
    assert not [item for item in api["env"] if item["name"].startswith("AGENT_BOM_POSTGRES_POOL_")]
    assert api["listenerAttestation"] == {"fromSecret": True}
    assert api["envFrom"] == [{"secretRef": {"name": "api-auth"}}]


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
@pytest.mark.parametrize("shared_delivery", [False, True])
def test_values_render_against_the_chart(tmp_path: Path, shared_delivery: bool) -> None:
    values = tmp_path / "values.json"
    values.write_text(json.dumps(_script().helm_values("agent-bom:local", shared_delivery=shared_delivery)))
    rendered = subprocess.run(
        ["helm", "template", "runtime-proof", str(ROOT / "deploy/helm/agent-bom"), "-n", "proof", "-f", str(values)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rendered.returncode == 0, rendered.stderr
