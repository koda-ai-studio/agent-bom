"""Tests for CrossAgentCorrelator — cross-agent behavioral detection."""

from __future__ import annotations

import time

from agent_bom.runtime.detectors import CrossAgentCorrelator

# ── record_call ──────────────────────────────────────────────────────────────


def test_record_call_stores_entry():
    """record_call stores an entry for the given agent."""
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "read_file", ts)
    assert "agent-A" in c._agent_calls
    assert len(c._agent_calls["agent-A"]) == 1
    assert c._agent_calls["agent-A"][0]["tool"] == "read_file"
    assert c._agent_calls["agent-A"][0]["timestamp"] == ts


def test_record_call_trims_to_max_history():
    """History is trimmed to _max_history entries."""
    c = CrossAgentCorrelator()
    c._max_history = 5
    ts = time.time()
    for i in range(10):
        c.record_call("agent-A", f"tool_{i}", ts + i)
    assert len(c._agent_calls["agent-A"]) == 5
    # Keeps most recent entries
    assert c._agent_calls["agent-A"][0]["tool"] == "tool_5"


def test_record_call_multiple_agents():
    """Different agent IDs are tracked independently."""
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "read_file", ts)
    c.record_call("agent-B", "write_file", ts)
    c.record_call("agent-C", "exec_cmd", ts)
    assert len(c._agent_calls) == 3


# ── detect_lateral_movement ──────────────────────────────────────────────────


def test_detect_lateral_movement_no_alerts_below_threshold():
    """No alerts when fewer than 3 agents use the same tool."""
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "read_file", ts)
    c.record_call("agent-B", "read_file", ts)
    alerts = c.detect_lateral_movement()
    assert alerts == []


def test_detect_lateral_movement_fires_at_three_agents():
    """Alert fires when 3 agents use the same tool in the 5-minute window."""
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "get_credentials", ts)
    c.record_call("agent-B", "get_credentials", ts)
    c.record_call("agent-C", "get_credentials", ts)
    alerts = c.detect_lateral_movement()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "cross_agent_tool_convergence"
    assert alert["tool"] == "get_credentials"
    assert set(alert["agents"]) == {"agent-A", "agent-B", "agent-C"}
    assert alert["severity"] == "high"


def test_detect_lateral_movement_fires_at_four_agents():
    """Alert fires and reports all agents when 4+ agents converge."""
    c = CrossAgentCorrelator()
    ts = time.time()
    for name in ["A", "B", "C", "D"]:
        c.record_call(f"agent-{name}", "exfil_tool", ts)
    alerts = c.detect_lateral_movement()
    assert len(alerts) == 1
    assert len(alerts[0]["agents"]) == 4


def test_detect_lateral_movement_ignores_stale_calls():
    """Calls older than 5 minutes are excluded from lateral movement detection."""
    c = CrossAgentCorrelator()
    stale_ts = time.time() - 400  # older than 5-minute window
    c.record_call("agent-A", "read_file", stale_ts)
    c.record_call("agent-B", "read_file", stale_ts)
    c.record_call("agent-C", "read_file", stale_ts)
    alerts = c.detect_lateral_movement()
    assert alerts == []


def test_detect_lateral_movement_same_agent_not_double_counted():
    """One agent calling the same tool many times does not trigger the alert."""
    c = CrossAgentCorrelator()
    ts = time.time()
    for _ in range(10):
        c.record_call("agent-A", "read_file", ts)
    alerts = c.detect_lateral_movement()
    assert alerts == []


def test_detect_lateral_movement_multiple_tools():
    """Alerts are generated independently for each tool that crosses threshold."""
    c = CrossAgentCorrelator()
    ts = time.time()
    for name in ["A", "B", "C"]:
        c.record_call(f"agent-{name}", "tool_one", ts)
        c.record_call(f"agent-{name}", "tool_two", ts)
    alerts = c.detect_lateral_movement()
    alerted_tools = {a["tool"] for a in alerts}
    assert "tool_one" in alerted_tools
    assert "tool_two" in alerted_tools


# ── compute_baseline ─────────────────────────────────────────────────────────


def test_compute_baseline_empty_history():
    """Baseline for unknown agent is an empty dict."""
    c = CrossAgentCorrelator()
    result = c.compute_baseline("agent-X")
    assert result == {}


def test_compute_baseline_single_tool():
    """Single-tool baseline has frequency 1.0."""
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "read_file", ts)
    baseline = c.compute_baseline("agent-A")
    assert baseline == {"read_file": 1.0}


def test_compute_baseline_two_tools_equal():
    """Two tools called equally often each have frequency 0.5."""
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "read_file", ts)
    c.record_call("agent-A", "write_file", ts)
    baseline = c.compute_baseline("agent-A")
    assert abs(baseline["read_file"] - 0.5) < 1e-9
    assert abs(baseline["write_file"] - 0.5) < 1e-9


def test_compute_baseline_frequencies_sum_to_one():
    """All baseline frequencies sum to 1.0."""
    c = CrossAgentCorrelator()
    ts = time.time()
    calls = ["read_file", "read_file", "write_file", "exec_cmd"]
    for tool in calls:
        c.record_call("agent-A", tool, ts)
    baseline = c.compute_baseline("agent-A")
    assert abs(sum(baseline.values()) - 1.0) < 1e-9


# ── detect_anomaly ───────────────────────────────────────────────────────────


def test_detect_anomaly_no_baseline_returns_false():
    """No baseline stored means no anomaly reported."""
    c = CrossAgentCorrelator()
    assert c.detect_anomaly("agent-A", "new_tool") is False


def test_detect_anomaly_tool_in_baseline_not_anomalous():
    """Tool present in baseline is not flagged as anomalous."""
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "read_file", ts)
    c.update_baseline("agent-A")
    assert c.detect_anomaly("agent-A", "read_file") is False


def test_detect_anomaly_new_tool_is_anomalous():
    """Tool absent from baseline is flagged as anomalous."""
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "read_file", ts)
    c.update_baseline("agent-A")
    assert c.detect_anomaly("agent-A", "exec_cmd") is True


def test_update_baseline_then_detect_anomaly():
    """update_baseline stores baseline; new tool is then anomalous."""
    c = CrossAgentCorrelator()
    ts = time.time()
    for tool in ["read_file", "write_file", "list_dir"]:
        c.record_call("agent-A", tool, ts)
    c.update_baseline("agent-A")

    # Known tools are not anomalous
    assert c.detect_anomaly("agent-A", "read_file") is False
    assert c.detect_anomaly("agent-A", "write_file") is False

    # Unknown tool is anomalous
    assert c.detect_anomaly("agent-A", "drop_database") is True


def test_record_call_matures_baseline_and_reports_novel_tool_once():
    c = CrossAgentCorrelator()
    ts = time.time()

    for index in range(20):
        assert c.record_call("agent-A", "read_file", ts + index) is None
    assert c._baselines["agent-A"] == {"read_file": 1.0}

    assert c.record_call("agent-A", "drop_database", ts + 20) == {
        "agent_id": "agent-A",
        "tool": "drop_database",
        "baseline_size": 20,
    }
    assert c.record_call("agent-A", "drop_database", ts + 21) is None


def test_record_call_refreshes_baseline_every_configured_interval():
    c = CrossAgentCorrelator(min_baseline_calls=3, baseline_refresh_calls=2)
    ts = time.time()
    for index in range(3):
        c.record_call("agent-A", "read_file", ts + index)

    assert c.record_call("agent-A", "new_tool", ts + 3)["baseline_size"] == 3
    c.record_call("agent-A", "read_file", ts + 4)
    assert set(c._baselines["agent-A"]) == {"read_file", "new_tool"}
    assert c.record_call("agent-A", "new_tool", ts + 5) is None


def test_record_call_evicts_least_recently_used_agent_state():
    c = CrossAgentCorrelator(min_baseline_calls=1, max_agents=2)
    ts = time.time()
    c.record_call("agent-A", "read_file", ts)
    c.record_call("agent-B", "read_file", ts + 1)
    c.record_call("agent-A", "read_file", ts + 2)
    c.record_call("agent-C", "read_file", ts + 3)

    assert list(c._agent_calls) == ["agent-A", "agent-C"]
    assert set(c._baselines) == {"agent-A", "agent-C"}
    assert set(c._baseline_sizes) == {"agent-A", "agent-C"}
    assert set(c._calls_since_baseline) == {"agent-A", "agent-C"}
    assert set(c._reported_novel) == {"agent-A", "agent-C"}


def test_rare_tool_in_mature_baseline_is_not_novel():
    c = CrossAgentCorrelator()
    ts = time.time()
    c.record_call("agent-A", "rare_tool", ts)
    for index in range(19):
        c.record_call("agent-A", "read_file", ts + index + 1)

    assert c._baselines["agent-A"]["rare_tool"] == 0.05
    assert c.record_call("agent-A", "rare_tool", ts + 20) is None
    assert c.record_call("agent-B", "new_tool", ts + 21) is None


def test_evicted_agent_restarts_warmup_without_old_novelty_state():
    c = CrossAgentCorrelator(min_baseline_calls=2, max_agents=1)
    ts = time.time()
    for _ in range(2):
        c.record_call("agent-A", "read_file", ts)
    assert c.record_call("agent-A", "new_tool", ts) is not None
    c.record_call("agent-B", "read_file", ts)

    assert c.record_call("agent-A", "new_tool", ts) is None
    assert "agent-A" not in c._baselines
    assert c.record_call("agent-A", "read_file", ts) is None
    assert c.record_call("agent-A", "another_tool", ts)["baseline_size"] == 2
