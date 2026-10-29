import shlex

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._quickstart import _control_plane_command, _resolve_quickstart_databases


def test_quickstart_defaults_follow_configured_state_directory(monkeypatch, tmp_path):
    state = tmp_path / "isolated state"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(state))
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_GRAPH_DB", raising=False)
    database, graph = _resolve_quickstart_databases({"AGENT_BOM_STATE_DIR": str(state)})
    assert database == state / "control-plane.db"
    assert graph == database
    assert not state.exists(), "resolving a path must not create a store"


def test_quickstart_handoff_preserves_custom_state_database(monkeypatch, tmp_path):
    state = tmp_path / "isolated state"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(state))
    database = state / "control-plane.db"
    tokens = shlex.split(_control_plane_command(control_plane_db=database, graph_db=database, port=18422))
    assert tokens[tokens.index("--persist") + 1] == str(database)
    assert f"AGENT_BOM_STATE_DIR={state}" in tokens


def test_quickstart_plan_uses_configured_databases(monkeypatch, tmp_path):
    state = tmp_path / "isolated state"
    database = tmp_path / "explicit control.db"
    graph = tmp_path / "explicit graph.db"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(state))
    monkeypatch.setenv("AGENT_BOM_DB", str(database))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(graph))
    result = CliRunner().invoke(main, ["quickstart", "--dry-run", "--offline"])
    assert result.exit_code == 0
    command = next(line.strip() for line in result.output.splitlines() if "agent-bom serve --persist" in line)
    tokens = shlex.split(command)
    assert tokens[tokens.index("--persist") + 1] == str(database)
    assert f"AGENT_BOM_GRAPH_DB={graph}" in tokens
    assert f"AGENT_BOM_STATE_DIR={state}" in tokens
