"""An incomplete export must never destroy the previously published report."""

import json
import os
import stat

import pytest

from agent_bom.models import AIBOMReport
from agent_bom.output import json_fmt, json_writer


def test_encoding_failure_preserves_existing_report(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    output.write_text('{"previous": true}\n')
    monkeypatch.setattr(json_fmt, "to_redacted_json", lambda *a, **kw: {"first": "written", "last": object()})
    with pytest.raises(TypeError):
        json_fmt.export_json(AIBOMReport(), str(output))
    assert output.read_text() == '{"previous": true}\n'
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.parametrize("existing", [False, True])
def test_partial_write_failure_does_not_publish_a_report(tmp_path, monkeypatch, existing):
    output = tmp_path / "report.json"
    if existing:
        output.write_text("previous")

    def interrupted(data, fh):
        fh.write('{"partial":')
        raise OSError("injected disk failure")

    monkeypatch.setattr(json_writer, "write_json_document", interrupted)
    with pytest.raises(OSError, match="injected"):
        json_fmt.export_json(AIBOMReport(), str(output))
    assert output.read_text() == "previous" if existing else not output.exists()
    assert list(tmp_path.iterdir()) == ([output] if existing else [])


@pytest.mark.parametrize("operation", ["fsync", "replace"])
def test_publication_failure_preserves_previous_file(tmp_path, monkeypatch, operation):
    output = tmp_path / "report.json"
    output.write_text("previous")

    def fail(*args):
        raise OSError("injected publication failure")

    monkeypatch.setattr(json_writer.os, operation, fail)
    with pytest.raises(OSError, match="injected"):
        json_fmt.export_json(AIBOMReport(), str(output))
    assert output.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode and symlink contract")
def test_atomic_replacement_preserves_symlink_and_target_permissions(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("previous")
    target.chmod(0o640)
    link = tmp_path / "report.json"
    link.symlink_to(target)
    json_fmt.export_json(AIBOMReport(), str(link), report_json={"complete": True})
    assert link.is_symlink()
    assert json.loads(target.read_text()) == {"complete": True}
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_successful_export_remains_valid_redacted_json(tmp_path):
    output = tmp_path / "report.json"
    json_fmt.export_json(AIBOMReport(), str(output), report_json={"key": "api_key=private-value", "rows": [1, 2]})
    assert json.loads(output.read_text())["rows"] == [1, 2]
    assert "private-value" not in output.read_text()
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires named pipe support")
def test_atomic_export_never_replaces_a_special_file(tmp_path):
    output = tmp_path / "pipe"
    os.mkfifo(output)
    with pytest.raises(ValueError, match="regular file"):
        json_fmt.export_json(AIBOMReport(), str(output))
    assert stat.S_ISFIFO(output.stat().st_mode)
    assert list(tmp_path.iterdir()) == [output]
