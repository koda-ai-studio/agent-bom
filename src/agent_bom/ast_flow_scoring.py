"""Severity, CWE and OWASP LLM classification for native AST flow findings.

One table drives the side-block rows (``agent-bom code`` JSON), the unified
``Finding`` promotion and SARIF rule metadata, so a taint category can never
rank differently on two surfaces.
"""

from __future__ import annotations

CRITICAL_MARKERS: tuple[str, ...] = ("command_execution", "unsafe_deserialization", "dynamic_code_execution")
HIGH_MARKERS: tuple[str, ...] = (
    "credential_file_access",
    "dangerous",
    "unguarded_tool_sink",
    "command_string",
    "dynamic_require",
    "path_access",
    "path_traversal",
    "privilege_escalation",
    "sql",
    "ssrf",
    "xss",
    "llm_prompt",
)
SECURITY_MARKERS: tuple[str, ...] = (*CRITICAL_MARKERS, *HIGH_MARKERS)

# Sink class -> CWE. Markers are substrings of the detector category.
CWE_BY_MARKER: dict[str, str] = {
    "command_execution": "CWE-78",
    "command_string": "CWE-78",
    "unsafe_deserialization": "CWE-502",
    "dynamic_code_execution": "CWE-95",
    "dynamic_require": "CWE-829",
    "path_access": "CWE-22",
    "path_traversal": "CWE-22",
    "sql": "CWE-89",
    "ssrf": "CWE-918",
    "xss": "CWE-79",
    "llm_prompt": "CWE-1427",
}
# Generic "dangerous call" categories carry no sink class; the sink name decides.
_SINK_CWE: tuple[tuple[tuple[str, ...], str], ...] = (
    (("child_process", "os.system", "os.popen", "subprocess", "popen", "spawn", "execsync"), "CWE-78"),
    (("eval", "exec", "function", "vm.", "compile"), "CWE-95"),
    (("pickle", "marshal", "yaml.load", "unserialize", "deserialize"), "CWE-502"),
    (("innerhtml", "document.write", "dangerouslysetinnerhtml"), "CWE-79"),
    (("execute", "query", "cursor", "raw(", "rawquery"), "CWE-89"),
)
_LLM_MARKERS: tuple[str, ...] = ("llm_prompt", "prompt_injection")
_OWASP_LLM_PROMPT_INJECTION = "LLM01"


def is_security_flow_category(category: str) -> bool:
    lowered = category.lower()
    return any(marker in lowered for marker in SECURITY_MARKERS)


def flow_severity(category: str) -> str:
    """``critical`` for code/command/deserialization sinks, ``high`` for other security sinks, else ``medium``."""
    lowered = category.lower()
    if any(marker in lowered for marker in CRITICAL_MARKERS):
        return "critical"
    if any(marker in lowered for marker in HIGH_MARKERS):
        return "high"
    return "medium"


def flow_cwe_ids(category: str, sink: str = "") -> list[str]:
    """CWE ids for a flow category, falling back to the sink name for generic categories."""
    lowered = category.lower()
    cwes = {cwe for marker, cwe in CWE_BY_MARKER.items() if marker in lowered}
    if not cwes and sink:
        sink_lower = sink.lower()
        for needles, cwe in _SINK_CWE:
            if any(needle in sink_lower for needle in needles):
                cwes.add(cwe)
                break
    return sorted(cwes)


def flow_owasp_llm_tags(category: str) -> list[str]:
    lowered = category.lower()
    return [_OWASP_LLM_PROMPT_INJECTION] if any(marker in lowered for marker in _LLM_MARKERS) else []
