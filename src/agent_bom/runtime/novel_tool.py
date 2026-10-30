"""Alert projection for per-agent novel-tool evidence."""

from agent_bom.runtime.detectors import Alert, AlertSeverity


def build_novel_tool_alert(evidence: dict) -> dict:
    """Build a sanitized, warn-only alert without changing enforcement state."""
    agent_id = str(evidence.get("agent_id", ""))
    tool_name = str(evidence.get("tool", ""))
    return Alert(
        detector="cross_agent_correlator",
        severity=AlertSeverity.MEDIUM,
        message=f"Agent {agent_id!r} called tool {tool_name!r} outside its established baseline",
        details=evidence,
    ).to_dict()
