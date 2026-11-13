"""The local vulnerability DB follows AGENT_BOM_STATE_DIR, and doctor / db status name the path used."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _env(tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENT_BOM_")}
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "PYTHONPATH": str(ROOT / "src"),
            "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
            "NO_COLOR": "1",
            "COLUMNS": "400",
        }
    )
    env.update(extra)
    (tmp_path / "home").mkdir(exist_ok=True)
    return env


def _python(env: dict[str, str], code: str) -> str:
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=120, check=True)
    return out.stdout.strip()


def _cli(env: dict[str, str], *args: str) -> str:
    out = subprocess.run([sys.executable, "-m", "agent_bom", *args], env=env, capture_output=True, text=True, timeout=180)
    return out.stdout + out.stderr


def test_db_path_defaults_under_the_state_dir(tmp_path: Path) -> None:
    state = tmp_path / "state"
    env = _env(tmp_path, AGENT_BOM_STATE_DIR=str(state))
    printed = _python(env, "from agent_bom.db.schema import DB_PATH; print(DB_PATH)")
    assert Path(printed).resolve() == (state / "db" / "vulns.db").resolve()


def test_explicit_db_path_still_wins_over_the_state_dir(tmp_path: Path) -> None:
    explicit = tmp_path / "elsewhere" / "custom.db"
    env = _env(tmp_path, AGENT_BOM_STATE_DIR=str(tmp_path / "state"), AGENT_BOM_DB_PATH=str(explicit))
    printed = _python(env, "from agent_bom.db.schema import DB_PATH; print(DB_PATH)")
    assert Path(printed).resolve() == explicit.resolve()


def test_without_state_dir_the_db_stays_under_home(tmp_path: Path) -> None:
    env = _env(tmp_path)
    printed = _python(env, "from agent_bom.db.schema import DB_PATH; print(DB_PATH)")
    assert Path(printed).resolve() == (tmp_path / "home" / ".agent-bom" / "db" / "vulns.db").resolve()


def test_db_path_inside_a_state_dir_outside_home_is_accepted(monkeypatch) -> None:
    from agent_bom.db.schema import _validated_db_path

    state = "/opt/agent-bom-state-under-test"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", state)
    assert _validated_db_path(f"{state}/db/vulns.db") == Path(f"{state}/db/vulns.db")


def test_db_status_and_path_and_doctor_name_the_state_dir_db(tmp_path: Path) -> None:
    state = tmp_path / "state"
    env = _env(tmp_path, AGENT_BOM_STATE_DIR=str(state), AGENT_BOM_OFFLINE="1")
    expected = str((state / "db" / "vulns.db"))

    assert expected in _cli(env, "db", "path")
    assert expected in _cli(env, "db", "status")
    doctor = _cli(env, "doctor")
    assert "Vuln DB" in doctor
    assert expected in doctor.replace("\n", "")


def _touch_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")


def test_an_existing_home_db_is_still_used_when_the_state_dir_has_none(tmp_path: Path) -> None:
    legacy = tmp_path / "home" / ".agent-bom" / "db" / "vulns.db"
    env = _env(tmp_path, AGENT_BOM_STATE_DIR=str(tmp_path / "state"))
    _touch_db(legacy)
    printed = _python(env, "from agent_bom.db.schema import DB_PATH; print(DB_PATH)")
    assert Path(printed).resolve() == legacy.resolve()


def test_a_state_dir_db_wins_over_the_home_db(tmp_path: Path) -> None:
    state = tmp_path / "state"
    env = _env(tmp_path, AGENT_BOM_STATE_DIR=str(state))
    _touch_db(tmp_path / "home" / ".agent-bom" / "db" / "vulns.db")
    _touch_db(state / "db" / "vulns.db")
    printed = _python(env, "from agent_bom.db.schema import DB_PATH; print(DB_PATH)")
    assert Path(printed).resolve() == (state / "db" / "vulns.db").resolve()


def test_explicit_db_path_wins_over_the_home_db_fallback(tmp_path: Path) -> None:
    explicit = tmp_path / "elsewhere" / "custom.db"
    env = _env(tmp_path, AGENT_BOM_STATE_DIR=str(tmp_path / "state"), AGENT_BOM_DB_PATH=str(explicit))
    _touch_db(tmp_path / "home" / ".agent-bom" / "db" / "vulns.db")
    printed = _python(env, "from agent_bom.db.schema import DB_PATH; print(DB_PATH)")
    assert Path(printed).resolve() == explicit.resolve()
