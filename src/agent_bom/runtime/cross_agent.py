"""Bounded cross-agent behavior history and per-agent tool baselines."""

from __future__ import annotations

import time


class CrossAgentCorrelator:
    """Detect suspicious patterns across multiple agent sessions.

    Maintains per-agent tool call history and detects lateral movement
    when multiple agents converge on the same sensitive tools within a
    short time window — a strong signal of coordinated compromise or
    credential-sharing between agents.
    """

    def __init__(self, *, min_baseline_calls: int = 20, baseline_refresh_calls: int = 10, max_agents: int = 1024) -> None:
        self._agent_calls: dict[str, list[dict]] = {}  # agent_id -> recent calls, in LRU order
        self._baselines: dict[str, dict] = {}  # agent_id -> tool frequency baseline
        self._baseline_sizes: dict[str, int] = {}
        self._calls_since_baseline: dict[str, int] = {}
        self._reported_novel: dict[str, set[str]] = {}
        self._max_history = 1000
        self._min_baseline_calls = max(1, min_baseline_calls)
        self._baseline_refresh_calls = max(1, baseline_refresh_calls)
        self._max_agents = max(1, max_agents)

    def record_call(self, agent_id: str, tool_name: str, timestamp: float) -> dict | None:
        """Record a call and return evidence when a mature baseline sees a novel tool.

        Detection uses the previous baseline, before this call can contaminate it.
        A novel tool is reported once per baseline epoch to avoid alert floods.
        """
        baseline_size = self._baseline_sizes.get(agent_id, len(self._agent_calls.get(agent_id, [])))
        novel = self.detect_anomaly(agent_id, tool_name) and tool_name not in self._reported_novel.get(agent_id, set())

        calls = self._agent_calls.pop(agent_id, None)
        if calls is None:
            if len(self._agent_calls) >= self._max_agents:
                oldest = next(iter(self._agent_calls))
                states = (self._agent_calls, self._baselines, self._baseline_sizes, self._calls_since_baseline, self._reported_novel)
                for state in states:
                    state.pop(oldest, None)
            calls = []
            self._calls_since_baseline[agent_id] = 0
            self._reported_novel[agent_id] = set()
        self._agent_calls[agent_id] = calls
        calls.append({"tool": tool_name, "timestamp": timestamp})
        if len(calls) > self._max_history:
            self._agent_calls[agent_id] = calls[-self._max_history :]

        self._calls_since_baseline[agent_id] += 1
        if len(calls) >= self._min_baseline_calls and (
            agent_id not in self._baselines or self._calls_since_baseline[agent_id] >= self._baseline_refresh_calls
        ):
            self.update_baseline(agent_id)

        if novel:
            self._reported_novel[agent_id].add(tool_name)
            return {"agent_id": agent_id, "tool": tool_name, "baseline_size": baseline_size}
        return None

    def detect_lateral_movement(self) -> list[dict]:
        """Detect when multiple agents access the same sensitive tools in sequence.

        Flags tools used by 3 or more distinct agents within a 5-minute window.
        This pattern indicates lateral movement, credential sharing, or a
        coordinated attack across agent sessions.

        Returns:
            List of alert dicts with type ``cross_agent_tool_convergence``.
        """
        alerts: list[dict] = []
        recent_window = time.time() - 300  # 5-minute window

        # Collect which agents used each tool in the window
        tool_agents: dict[str, list[str]] = {}
        for agent_id, calls in self._agent_calls.items():
            for call in calls:
                if call["timestamp"] > recent_window:
                    tool = call["tool"]
                    if tool not in tool_agents:
                        tool_agents[tool] = []
                    if agent_id not in tool_agents[tool]:
                        tool_agents[tool].append(agent_id)

        # Flag tools used by 3+ different agents in the window
        for tool, agents in tool_agents.items():
            if len(agents) >= 3:
                alerts.append(
                    {
                        "type": "cross_agent_tool_convergence",
                        "tool": tool,
                        "agents": agents,
                        "severity": "high",
                        "message": (
                            f"Tool '{tool}' used by {len(agents)} agents in 5-minute window — "
                            "possible lateral movement or coordinated access"
                        ),
                    }
                )

        return alerts

    def compute_baseline(self, agent_id: str) -> dict:
        """Compute tool frequency baseline for anomaly detection.

        Returns a dict mapping tool name to its relative frequency (0.0–1.0)
        in the agent's historical call log.
        """
        calls = self._agent_calls.get(agent_id, [])
        freq: dict[str, int] = {}
        for call in calls:
            freq[call["tool"]] = freq.get(call["tool"], 0) + 1
        total = sum(freq.values()) or 1
        return {tool: count / total for tool, count in freq.items()}

    def update_baseline(self, agent_id: str) -> None:
        """Compute and store the tool frequency baseline for an agent.

        Should be called periodically (e.g. after every N calls) to keep
        the baseline current without paying compute cost on every call.
        """
        self._baselines[agent_id] = self.compute_baseline(agent_id)
        self._baseline_sizes[agent_id] = len(self._agent_calls.get(agent_id, []))
        self._calls_since_baseline[agent_id] = 0
        self._reported_novel[agent_id] = set()

    def detect_anomaly(self, agent_id: str, tool_name: str) -> bool:
        """Check if a tool call is anomalous based on historical baseline.

        Returns True when the tool has never been seen in the stored baseline,
        which indicates either a new capability being exercised or an agent
        behaving outside its normal operational envelope.

        The baseline must be stored via ``update_baseline()`` before this
        method will return meaningful results.  Returns False (not anomalous)
        when no baseline exists for the agent.
        """
        baseline = self._baselines.get(agent_id)
        if not baseline:
            return False
        expected_freq = baseline.get(tool_name, 0.0)
        # Tool never seen in baseline = anomalous
        return expected_freq == 0.0
