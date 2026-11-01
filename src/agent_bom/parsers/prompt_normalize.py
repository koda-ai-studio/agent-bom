"""Obfuscation-resistant text projections shared by the prompt, skill and MCP descriptor scanners."""

from __future__ import annotations

import base64
import re
import unicodedata

from agent_bom.runtime.text_normalize import HOMOGLYPHS, reveal_hidden_text

# ── Obfuscation normalization ──────────────────────────────────────────────
# Adversarial prompt injections evade naive keyword matching via Unicode
# homoglyphs, zero-width separators, leetspeak, and base64 encoding. We match
# every pattern against BOTH the raw text and a normalized projection so these
# bypasses are caught. Detection only — the projection is never persisted.

# Zero-width / invisible separators an attacker inserts between letters.
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠⁡⁢⁣⁤﻿­͏᠎"), None)
# Common Cyrillic/Greek homoglyphs → Latin (NFKC misses these script
# confusables). Shared with the policy engine so detection and enforcement
# cannot drift apart on what counts as a look-alike.
_HOMOGLYPHS = HOMOGLYPHS
# Leetspeak substitutions (applied to a separate projection to limit false positives).
_LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def matching_projections(text: str) -> list[str]:
    """The obfuscation-resistant projections of ``text``, one string each.

    Decodes invisible tag/selector payloads, folds Unicode (NFKC + homoglyphs), strips
    zero-width separators, de-leets, and decodes base64 runs — so injections hidden via
    invisible Unicode, homoglyph, zero-width, leetspeak, or base64 still match. Callers
    search each projection on its own: a pattern must never span the seam between two
    projections, or ``run`` at the end of one and ``shell command`` at the start of the
    next would read as a shell instruction.
    """
    folded = unicodedata.normalize("NFKC", reveal_hidden_text(text)).translate(_ZERO_WIDTH).translate(_HOMOGLYPHS)
    decoded: list[str] = []
    for m in _B64_RUN.finditer(text):
        chunk = m.group(0)
        try:
            raw = base64.b64decode(chunk + "===", validate=False).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            continue
        if len(raw) > 6 and sum(c.isprintable() for c in raw) / len(raw) > 0.8:
            decoded.append(raw)
    return [folded, folded.translate(_LEET), *decoded]


def normalize_for_matching(text: str) -> str:
    """The :func:`matching_projections` joined, for presence detection only (no match may span two)."""
    return "\n".join(matching_projections(text))


__all__ = ["matching_projections", "normalize_for_matching"]
