"""JSON written to a file is compact by default; stdout stays indented.

Indentation was about a third of a JSON report's bytes. The parsed document is
identical either way, so every consumer that loads the file is unaffected.
"""

from __future__ import annotations

import gzip
import io
import json
import os

import click
import pytest
from click.testing import CliRunner

from agent_bom.cli.options_pretty_json import PRETTY_JSON_OPTION
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import json_fmt
from agent_bom.output.badge import export_badge
from agent_bom.output.cyclonedx_fmt import export_cyclonedx
from agent_bom.output.json_writer import pretty_json_requested, write_json_file
from agent_bom.output.sarif import export_sarif
from agent_bom.output.spdx2_fmt import export_spdx2
from agent_bom.output.spdx_fmt import export_spdx

_DOCUMENT = {
    "document_type": "AI-BOM",
    "unicode": 'café ☃ "q" \\ x\nline',
    "numbers": [0, -1, 1.5, True, None],
    "rows": [{"name": f"pkg-{i}", "tags": ["a", "b"], "nested": {"k": i}} for i in range(700)],
    "empty": {"a": {}, "b": []},
}
_VOLATILE = {"timestamp", "created", "generated_at", "serialNumber", "documentNamespace", "creationInfo", "scan_id"}


@pytest.fixture(autouse=True)
def _no_pretty_env(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_PRETTY_JSON", raising=False)


def test_file_is_compact_and_parses_to_the_same_document(tmp_path):
    output = tmp_path / "doc.json"
    write_json_file(_DOCUMENT, str(output))
    text = output.read_text(encoding="utf-8")
    assert text == json.dumps(_DOCUMENT, separators=(",", ":"))
    assert json.loads(text) == json.loads(json.dumps(_DOCUMENT, indent=2))


def test_pretty_env_and_explicit_flag_keep_indentation(tmp_path, monkeypatch):
    explicit = tmp_path / "explicit.json"
    write_json_file(_DOCUMENT, str(explicit), compact=False)
    assert explicit.read_text(encoding="utf-8") == json.dumps(_DOCUMENT, indent=2) + "\n"
    monkeypatch.setenv("AGENT_BOM_PRETTY_JSON", "true")
    from_env = tmp_path / "env.json"
    write_json_file(_DOCUMENT, str(from_env))
    assert from_env.read_bytes() == explicit.read_bytes()


@pytest.mark.parametrize(
    ("value", "expected"),
    [("", False), ("0", False), ("false", False), ("no", False), ("off", False), ("1", True), ("yes", True), ("TRUE", True)],
)
def test_pretty_env_values(monkeypatch, value, expected):
    monkeypatch.setenv("AGENT_BOM_PRETTY_JSON", value)
    assert pretty_json_requested() is expected


def test_gzip_destination_is_compact_too(tmp_path):
    output = tmp_path / "doc.json.gz"
    write_json_file(_DOCUMENT, str(output))
    assert gzip.decompress(output.read_bytes()).decode("utf-8") == json.dumps(_DOCUMENT, separators=(",", ":"))


def _report() -> AIBOMReport:
    pkg = Package(name="left-pad", version="1.0.0", ecosystem="npm")
    server = MCPServer(name="srv", command="npx", packages=[pkg])
    return AIBOMReport(agents=[Agent(name="a", agent_type=AgentType.CUSTOM, config_path="/tmp/a", mcp_servers=[server])], blast_radii=[])


def _drop_volatile(value):
    if isinstance(value, dict):
        for key in list(value):
            if key in _VOLATILE:
                value.pop(key)
            else:
                _drop_volatile(value[key])
    elif isinstance(value, list):
        for item in value:
            _drop_volatile(item)


_EXPORTERS = {
    "json-v1": lambda r, p: json_fmt.export_json(r, p),
    "json-v2": lambda r, p: json_fmt.export_json(r, p, report_format="v2"),
    "cyclonedx": export_cyclonedx,
    "spdx3": export_spdx,
    "spdx2": export_spdx2,
    "sarif": lambda r, p: export_sarif(r, p),
    "badge": export_badge,
}


@pytest.mark.parametrize("name", sorted(_EXPORTERS))
def test_every_json_file_exporter_writes_compact_with_identical_content(tmp_path, monkeypatch, name):
    exporter = _EXPORTERS[name]
    report = _report()
    compact_path = tmp_path / "compact.json"
    exporter(report, str(compact_path))
    monkeypatch.setenv("AGENT_BOM_PRETTY_JSON", "1")
    pretty_path = tmp_path / "pretty.json"
    exporter(report, str(pretty_path))
    compact_text = compact_path.read_text(encoding="utf-8")
    pretty_text = pretty_path.read_text(encoding="utf-8")
    assert "\n" not in compact_text.rstrip("\n")
    assert "\n  " in pretty_text
    assert len(compact_text) < len(pretty_text)
    compact_doc, pretty_doc = json.loads(compact_text), json.loads(pretty_text)
    _drop_volatile(compact_doc)
    _drop_volatile(pretty_doc)
    assert compact_doc == pretty_doc


def test_stdout_json_stays_indented():
    buffer = io.StringIO()
    json_fmt.write_redacted_json(AIBOMReport(), buffer, report_json={"rows": [1, 2]})
    assert buffer.getvalue() == json.dumps({"rows": [1, 2]}, indent=2) + "\n"


def test_cli_pretty_json_flag_sets_env(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_PRETTY_JSON", "0")  # restored after the flag sets it

    @click.command()
    @PRETTY_JSON_OPTION
    def cmd():
        click.echo(os.environ.get("AGENT_BOM_PRETTY_JSON", ""))

    assert CliRunner().invoke(cmd, []).output.strip() == "0"
    assert CliRunner().invoke(cmd, ["--pretty-json"]).output.strip() == "1"
