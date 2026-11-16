"""Ephemeral-key warnings track configuration state, not cookie traffic."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest

from agent_bom.api import browser_session as sessions


@pytest.fixture
def warning(monkeypatch):
    for name in (
        "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY",
        "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_FILE",
        "AGENT_BOM_REQUIRE_BROWSER_SESSION_SIGNING_KEY",
        "AGENT_BOM_CONTROL_PLANE_REPLICAS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sessions, "_SIGNING_KEY_CACHE", None)
    monkeypatch.setattr(sessions, "_EPHEMERAL_WARNING_EMITTED", False, raising=False)
    logger = Mock()
    monkeypatch.setattr(sessions, "_logger", logger)
    return logger.warning


def test_concurrent_ephemeral_key_reads_warn_once(warning):
    with ThreadPoolExecutor(max_workers=4) as pool:
        keys = list(pool.map(lambda _: sessions._signing_key(), range(12)))
    assert all(key == sessions._EPHEMERAL_SIGNING_KEY for key in keys)
    warning.assert_called_once()
    assert "invalid after process restart" in warning.call_args.args[0]


def test_configured_key_then_removal_warns_again(warning, monkeypatch):
    first = sessions._signing_key()
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-warning-transition")
    assert sessions._signing_key() != first
    monkeypatch.delenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY")
    assert sessions._signing_key() == first
    assert sessions._signing_key() == first
    assert warning.call_count == 2


def test_warning_state_never_bypasses_cluster_requirement(warning, monkeypatch):
    sessions._signing_key()
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")
    for _ in range(2):
        with pytest.raises(sessions.BrowserSessionError, match="required for clustered"):
            sessions._signing_key()
    warning.assert_called_once()
