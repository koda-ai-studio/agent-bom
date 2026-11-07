"""CLI documents are consumable by implementations of CycloneDX 1.6."""

import json

from click.testing import CliRunner
from cyclonedx.model.bom import Bom
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from agent_bom.cli import main
from agent_bom.models import AIBOMReport
from agent_bom.output.cyclonedx_fmt import to_cyclonedx


def test_explicit_16_document_validates_with_official_consumer():
    document = to_cyclonedx(AIBOMReport(), spec_version="1.6")
    assert document["specVersion"] == "1.6"
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(document)) is None


def test_fs_cli_defaults_to_accepted_version(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    result = CliRunner().invoke(main, ["fs", str(tmp_path), "--offline", "-q", "-f", "cyclonedx", "-o", str(tmp_path / "report.cdx.json")])
    assert result.exit_code == 1  # Missing offline database is an explicit partial scan.
    raw = (tmp_path / "report.cdx.json").read_text()
    document = json.loads(raw)
    assert document["specVersion"] == "1.6"
    assert any(component.get("name") == "requests" for component in document["components"])
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(raw) is None

    consumed = Bom.from_json(document)
    assert any(component.name == "requests" for component in consumed.components)
