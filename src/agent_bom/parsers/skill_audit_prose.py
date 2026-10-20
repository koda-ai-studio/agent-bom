"""Decide whether a prohibition cue governs a behavioral match.

A cue only governs a match in the same sentence: before it ("Never run X")
or after it as an approval gate or predicate ("X only after review",
"X is not allowed"). A fresh imperative clause ("X and do not tell the
user") or a cue in a neighbouring sentence is the author's own wording
around a directive, not a prohibition of it. A quoted match introduced by
an example cue ("such as \"...\"") is a labelled example.
"""

from __future__ import annotations

import re

_SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)")

_TRAILING_CUE_RE = re.compile(
    r"\b(?:without\s+(?:(?:an?|prior|explicit|the)\s+){0,4}(?:explicit|prior|human|user|written|manual)|"
    r"(?:require[sd]?|need(?:s|ed)?|after|only\s+after|upon|following|pending|once)"
    r"\s+(?:(?:an?|explicit|prior|human|user|manual|written|the)\s+){0,4}"
    r"(?:review|approval|confirmation|consent|sign[-\s]?off|request)|"
    r"(?:is|are|be|was|were)\s+(?:not\s+(?:allowed|permitted)|never\s+allowed|forbidden|prohibited|disallowed|banned|blocked))\b",
    re.IGNORECASE,
)


_EXAMPLE_CUE_RE = re.compile(r"\b(?:such\s+as|e\.g\.|for\s+example|for\s+instance|like|phrases?)\b", re.IGNORECASE)
_OPENING_QUOTES = "\"'`\u201c\u2018"


def _is_labelled_example(content: str, match_start: int, before: str) -> bool:
    """A quoted match introduced by an example cue earlier in its sentence."""
    quoted = match_start > 0 and content[match_start - 1] in _OPENING_QUOTES
    return quoted and bool(_EXAMPLE_CUE_RE.search(before))


def _sentence_bounds(content: str, match_start: int, match_end: int, lo: int, hi: int) -> tuple[int, int]:
    start = lo
    for end in _SENTENCE_END_RE.finditer(content, lo, match_start):
        start = end.end()
    following = _SENTENCE_END_RE.search(content, match_end, hi)
    return start, following.end() if following else hi


def prohibition_governs(
    content: str,
    match_start: int,
    match_end: int,
    block: tuple[int, int],
    cue: re.Pattern[str],
    proximity: int,
) -> bool:
    """Return True when a prohibition cue in the match's sentence governs it."""
    sentence_start, sentence_end = _sentence_bounds(content, match_start, match_end, *block)
    before = content[max(sentence_start, match_start - proximity) : match_start]
    after = content[match_end : min(sentence_end, match_end + proximity)]
    if _is_labelled_example(content, match_start, before):
        return True
    return bool(cue.search(before) or _TRAILING_CUE_RE.search(after))
