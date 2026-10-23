"""Shared Unicode folding for adversarial text.

Detection already normalized text before matching (tool-poisoning scans in
``agent_bom.enforcement``, prompt-injection scans in
``agent_bom.parsers.prompt_scanner``). Enforcement did not, so a look-alike
tool name walked past the policy engine that was meant to stop it.

The folds live here so all three read the same definition. Nothing in this
module imports from the rest of the package: it is a leaf, safe to import from
the policy engine, the scanners, and the gateway alike.
"""

from __future__ import annotations

import re
import unicodedata
from typing import NamedTuple

# Zero-width and invisible characters commonly used for evasion.
# Written as escapes, not literals. Embedding raw bidirectional and
# zero-width characters in source is itself the trojan-source vector this
# module exists to defeat (bandit B613 flags it), and a reviewer cannot see
# what a literal contains. The escapes compile to the same class.
INVISIBLE_RE = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u034f\u115f\u1160\u17b4\u17b5]")

# Cyrillic/Greek/other script confusables → Latin. Unicode normalization does
# not fold these: they are distinct letters that merely *look* identical.
HOMOGLYPHS = {
    ord(src): dst
    for src, dst in {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "ѕ": "s",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "ո": "n",
        "һ": "h",
        "ɡ": "g",
        "ⅼ": "l",
        "α": "a",
        "ε": "e",
        "ο": "o",
        "ρ": "p",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "τ": "t",
    }.items()
}


# Text an attacker can carry invisibly. Unicode tag characters (U+E0000 block)
# mirror ASCII one-for-one and render as nothing; runs of variation selectors
# can carry arbitrary bytes, one selector per byte. Bidirectional embedding and
# isolate controls reorder what a reviewer sees without changing what a model
# reads. Tag characters after U+1F3F4 are subdivision-flag emoji, and a single
# selector after a glyph is ordinary emoji or text presentation.
_TAG_RUN_RE = re.compile("[\U000e0000-\U000e007f]+")
_SELECTOR_RUN_RE = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{2,}")
_BIDI_CONTROL_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
_FLAG_BASE = "\U0001f3f4"


class HiddenPayload(NamedTuple):
    """An invisible character run and the text it encodes."""

    start: int
    end: int
    kind: str  # "tag" | "variation_selector"
    decoded: str


def _decode_tags(run: str) -> str:
    return "".join(chr(ord(char) - 0xE0000) for char in run if 0xE0020 <= ord(char) <= 0xE007E)


def _decode_selectors(run: str) -> str:
    data = bytes(ord(char) - 0xFE00 if ord(char) <= 0xFE0F else ord(char) - 0xE0100 + 16 for char in run)
    return data.decode("utf-8", "replace")


def hidden_payloads(text: str) -> list[HiddenPayload]:
    """Return every invisible run in ``text`` that encodes characters."""
    found = [
        HiddenPayload(m.start(), m.end(), "tag", _decode_tags(m.group()))
        for m in _TAG_RUN_RE.finditer(text)
        if not (m.start() and text[m.start() - 1] == _FLAG_BASE)
    ]
    found += [
        HiddenPayload(m.start(), m.end(), "variation_selector", _decode_selectors(m.group())) for m in _SELECTOR_RUN_RE.finditer(text)
    ]
    return sorted((payload for payload in found if payload.decoded), key=lambda payload: payload.start)


def reveal_hidden_text(text: str) -> str:
    """Replace each invisible payload with the text it encodes, in place.

    Bidirectional controls are dropped. Everything else, including emoji flag
    and presentation sequences, is returned unchanged.
    """
    if text.isascii():
        return text
    parts: list[str] = []
    cursor = 0
    for payload in hidden_payloads(text):
        parts += [text[cursor : payload.start], payload.decoded]
        cursor = payload.end
    parts.append(text[cursor:])
    return _BIDI_CONTROL_RE.sub("", "".join(parts))


def normalize_text(text: str) -> str:
    """Reveal hidden payloads, strip invisible characters and apply NFKD.

    Decomposes ligatures and folds fullwidth forms. Script confusables are left
    alone — this projection is used for pattern scanning, where folding letters
    across scripts would broaden the patterns themselves.
    """
    return unicodedata.normalize("NFKD", INVISIBLE_RE.sub("", reveal_hidden_text(text)))


def normalize_identifier(name: str) -> str:
    """Fold a tool/identifier name to its canonical comparison form.

    Adds confusable folding and case folding on top of :func:`normalize_text`,
    because an identifier is compared for equality rather than scanned for
    patterns: ``dеlete_file`` (Cyrillic ``е``) and ``ｄｅｌｅｔｅ_file`` name the
    same tool as ``delete_file`` and must be governed as such.

    Only ever widen a DENY with this. Folding both sides of an *allowlist*
    comparison would let a look-alike unlock the tool the operator allowed.

    Case folding runs before the confusable table so an uppercase look-alike
    (``Е``, U+0415) folds through its lowercase form; the table only needs the
    lowercase mapping.
    """
    return normalize_text(name).casefold().translate(HOMOGLYPHS)
