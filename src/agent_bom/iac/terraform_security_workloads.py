"""Plain runtime model keys in supported container resources.

These are configuration checks, not secret validity checks: placeholders and
variable expressions still use the plain runtime environment value channel.
"""

from __future__ import annotations

import json
import re

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security_common import TfResource
from agent_bom.iac.terraform_security_hcl import attr, nested_blocks, tf_finding

_MODEL_KEY = re.compile(
    r"^(?:OPENAI|ANTHROPIC|AZURE_OPENAI|GOOGLE|GEMINI|COHERE|MISTRAL|GROQ|TOGETHER|DEEPSEEK|FIREWORKS|PERPLEXITY|XAI|HUGGINGFACE|HF)_(?:API_KEY|API_TOKEN|TOKEN)$"
)
_ENV_LIST = re.compile(r'\b"?environment"?\s*[:=]\s*\[')
_NAME = re.compile(r'\b"?name"?\s*[:=]\s*"([A-Z][A-Z0-9_]*)"')
_VALUE = re.compile(r'\b"?value"?\s*[:=]\s*(?!null\b)\S')


def _balanced_end(text: str, start: int, opening: str, closing: str) -> int:
    """Find a balanced delimiter without interpreting braces inside strings."""
    depth, quoted, escaped = 1, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if not depth:
                return i
    return len(text)


def _environment_entries(res: TfResource) -> list[tuple[int, str]]:
    if res.rtype != "aws_ecs_task_definition":
        return nested_blocks(res.block, "env")
    text = res.block
    definition = attr(text, "container_definitions")
    literal_offset = None
    if definition is not None and definition.string is not None:
        try:
            text = json.loads(definition.raw)
        except (ValueError, TypeError):
            return []
        literal_offset = definition.offset
    entries = []
    for match in _ENV_LIST.finditer(text):
        end = _balanced_end(text, match.end(), "[", "]")
        pos = match.end()
        while pos < end:
            start = text.find("{", pos, end)
            if start < 0:
                break
            stop = _balanced_end(text, start + 1, "{", "}")
            entries.append((start + 1 if literal_offset is None else literal_offset, text[start + 1 : stop]))
            pos = stop + 1
    return entries


def tf_sec_052(res: TfResource) -> list[IaCFinding]:
    """Model credentials belong in runtime secret references, never plain env values."""
    findings = []
    for offset, body in _environment_entries(res):
        name = _NAME.search(body)
        if name is None or not _MODEL_KEY.fullmatch(name.group(1)) or not _VALUE.search(body):
            continue
        findings.append(
            tf_finding(
                res,
                rule_id="TF-SEC-052",
                severity="high",
                title="Model API key in plain runtime environment",
                message=(
                    f"Resource '{res.rname}' configures {name.group(1)} through a plain environment value. "
                    "This is unsafe even for placeholders; the value is intentionally omitted."
                ),
                compliance=["NIST-IA-5"],
                remediation="Use ECS secrets, Azure secret_name, or Cloud Run value_source.secret_key_ref instead of a plain value.",
                offset=offset + name.start(),
            )
        )
    return findings
