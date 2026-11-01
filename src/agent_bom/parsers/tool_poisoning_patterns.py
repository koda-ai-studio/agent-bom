"""Hidden-instruction patterns for MCP tool, resource and prompt descriptors.

A poisoned descriptor tells the model to obey the server instead of the user:
an ``<IMPORTANT>`` block, "do not tell the user", a credential file to read, a
URL to post data to, a parameter to smuggle it through, or an order to run
before every other tool. Shared by the prompt-template scanner, the MCP
enforcement audit and the runtime proxy scanner.
"""

from __future__ import annotations

import base64
import binascii
import re

# MCP tool-description poisoning (high). Hidden instructions planted in a tool,
# resource or prompt descriptor so the model obeys the server, not the user.
# Each pattern is anchored on an instruction verb or markup and keeps every
# wildcard bounded, so matching stays linear on adversarial input.
_CREDENTIAL_FILE_PATHS = (
    r"~/\.ssh\b|\.ssh/|id_rsa\b|id_ed25519\b|id_ecdsa\b|~/\.aws\b|\.aws/credentials|~/\.gnupg|\.netrc\b|\.npmrc\b|"
    r"\.pypirc\b|\.docker/config\.json|\.kube/config|credentials\.json|~/\.config/gcloud"
)
_CONCEAL_VERBS = (
    r"(?:tell(?:ing)?|mention(?:ing)?|inform(?:ing)?|reveal(?:ing)?|disclos(?:e|ing)|show(?:ing)?|notify(?:ing)?|"
    r"alert(?:ing)?|warn(?:ing)?|display(?:ing)?|surfac(?:e|ing)|report(?:ing)?)"
)
TOOL_POISONING_PATTERNS = [
    (
        re.compile(
            r"""(?:<\s*/?\s*(?:important|system|admin|administrator|assistant|developer|hidden|secret|instructions?|override|priority)\b[^<>\n]{0,80}>"""
            r"""|\[\[\s*(?:system|important|admin|instructions?|hidden)\b"""
            r"""|<!--[^\n]{0,200}?\b(?:ignore|instructions?|do\s+not|don'?t|never|read|send|exfiltrat\w{0,3}|include|append|before|after|also|secret|credentials?|password|token)\b)""",
            re.IGNORECASE,
        ),
        "Hidden instruction block in descriptor",
    ),
    (
        re.compile(
            r"""\b(?:do\s+not|don'?t|never|without|not)\s+(?:ever\s+)?"""
            + _CONCEAL_VERBS
            + r"""(?:\s+(?:(?:these|those|the|your|my)\s+(?:instructions?|requests?|steps?|changes?|behaviou?r)"""
            r"""|this|that|it|anything|these|those|them))?"""
            r"""(?:\s+(?:about\s+)?(?:this|that|it))?\s+(?:to\s+)?(?:the\s+)?(?:user|human|operator|person|caller)\b""",
            re.IGNORECASE,
        ),
        "Instruction to conceal behaviour from the user",
    ),
    (
        re.compile(
            r"""\b(?:read|cat|open|load|fetch|retrieve|access|copy|dump|include|send|upload|attach|exfiltrate|grab|collect|print|echo|source)\b"""
            r"""[^\n<>]{0,40}?(?:""" + _CREDENTIAL_FILE_PATHS + r""")""",
            re.IGNORECASE,
        ),
        "Credential file read instruction",
    ),
    (
        re.compile(
            r"""\b(?:send|post|upload|forward|transmit|exfiltrate|leak|push|relay|mirror)\s+"""
            r"""(?:it|them|this|that|the|all|any|every|each|your|our|its|their|user'?s?|contents?|data|results?|output|file|key|token|secret|"""
            r"""credentials?|conversation|history|response|everything)\b[^\n<>]{0,80}?\bhttps?://""",
            re.IGNORECASE,
        ),
        "Exfiltration to an external URL",
    ),
    (
        re.compile(
            r"""\b(?:pass|include|insert|embed|append|attach|copy|put|place|send|supply|provide)\s+"""
            r"""(?:the\s+|its\s+|their\s+|all\s+|this\s+|that\s+|any\s+)?(?:file\s+|full\s+|entire\s+|raw\s+|complete\s+|resulting\s+)?"""
            r"""(?:contents?|value|data|output|results?|key|token|secret|text|listing|bytes|password|credentials?)\b[^\n<>]{0,60}?"""
            r"""\b(?:as|in|into|inside|via|through|within)\s+(?:a|an|the|this|that|its)?\s*(?:['"`][\w .-]{1,40}['"`]\s*)?"""
            r"""(?:parameter|argument|param|arg|field|note|sidenote|message|payload|header)\b""",
            re.IGNORECASE,
        ),
        "Smuggle data through a tool parameter",
    ),
    (
        re.compile(
            r"""\b(?:before|after|prior\s+to|whenever|every\s+time|each\s+time|instead\s+of)\s+(?:you\s+)?"""
            r"""(?:(?:call|calling|use|using|invoke|invoking|run|running|execut(?:e|ing))\s+)?"""
            r"""(?:this|that|any|every|each|another|other|the|all)\s+(?:other\s+)?(?:[\w.-]{1,40}\s+)?(?:tools?|functions?|calls?|requests?|servers?)\b""",
            re.IGNORECASE,
        ),
        "Tool-call sequencing or shadowing instruction",
    ),
]

# A base64 run long enough to carry an instruction; the decoded text must read
# as text (printable, mixed case) so hex digests and random ids never qualify.
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")


def encoded_payload_match(text: str) -> str | None:
    """The decoded text of the first base64 blob in ``text`` that reads as natural text, else ``None``."""
    for match in _B64_BLOB.finditer(text):
        chunk = match.group(0)
        if chunk.lower() == chunk or chunk.upper() == chunk:
            continue  # hex digests and single-case ids are not encoded prose
        try:
            raw = base64.b64decode(chunk + "===", validate=False).decode("utf-8", "ignore")
        except (ValueError, binascii.Error):
            continue
        if len(raw) >= 20 and sum(c.isprintable() for c in raw) / len(raw) > 0.9 and raw.count(" ") >= 2:
            return raw[:200]
    return None


__all__ = ["TOOL_POISONING_PATTERNS", "encoded_payload_match"]
