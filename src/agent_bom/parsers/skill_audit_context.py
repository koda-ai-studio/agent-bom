"""Prohibition / policy context guard: read a behavioral match as directive or documentation."""

from __future__ import annotations

import re

from agent_bom.parsers.skill_audit_prose import prohibition_governs

# ── Prohibition / policy context guard ──────────────────────────────────────
#
# Instruction files legitimately *enumerate* dangerous flags and commands in
# order to forbid them ("## Never — `git push --force`, `--no-verify`, …",
# "Do not disable the sandbox"). Matching the literal token there flags the
# repository's own governance docs as malicious. A behavioral match is read as
# policy prose when it sits under a prohibition heading, or when a prohibition
# cue ("never", "do not", "without explicit approval", …) governs it nearby.
# The cue must be *proximate* to the match (same list item / paragraph), so a
# real dangerous instruction elsewhere in the file is still detected.
#
# Prose context is authored by whoever wrote the file — i.e. by the attacker —
# so it can never *delete* evidence. Two rules bound it:
#
#   1. A suppressed match is DOWNGRADED, not dropped: it is emitted at low
#      severity with ``context="possibly_documentation"`` so the evidence still
#      reaches the report and the operator decides. Low + low-confidence
#      findings do not move the trust verdict (see ``trust_assessment``).
#   2. Suppression does not apply at all when the match is a runnable fenced
#      code block, or when the governing scope carries a line-anchored
#      agent-directed imperative ("Always …", "Before answering …",
#      "Auto-approve …"). Prose that *tells the agent to do the thing* is a
#      directive no matter what the heading above it claims.

_PROHIBITION_HEADING_RE = re.compile(
    r"^\s{0,3}#{1,6}\s+.*\b(?:never|don'?ts?|do\s+not|avoid|prohibit\w*|"
    r"forbidden|forbid|disallow\w*|anti[-\s]?patterns?|red\s+flags?|"
    r"examples?\s+to\s+(?:flag|detect|catch|block|reject)|detection\s+(?:examples|patterns|rules))\b",
    re.IGNORECASE,
)

_PROHIBITION_CUE_RE = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|must\s+never|shall\s+not|"
    r"should\s+not|cannot|can'?t|avoid|prohibit\w*|forbid\w*|forbidden|"
    r"disallow\w*|not\s+allowed|not\s+permitted|"
    r"without\s+(?:(?:an?|prior|explicit|the)\s+){0,4}"
    r"(?:explicit|prior|human|user|written|manual)|"
    r"(?:require[sd]?|need(?:s|ed)?|after|only\s+after|upon|following|pending|once)"
    r"\s+(?:(?:an?|explicit|prior|human|user|manual|written|the)\s+){0,4}"
    r"(?:review|approval|confirmation|consent|sign[-\s]?off|request)|"
    r"reject\w*|refus\w*)\b",
    re.IGNORECASE,
)

_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")

# A markdown code fence. Text inside one is a runnable command, not prose about
# a command, so a prohibition heading above it cannot excuse it.
_CODE_FENCE_RE = re.compile(r"^\s{0,3}(?:```|~~~)", re.MULTILINE)

# Agent-directed imperatives. Anchored to the start of a line (optionally after
# a list marker or bold run) so that policy prose which merely *contains* the
# word — "Do not run codex with --yolo; always require confirmation." — is not
# mistaken for a directive.
_AGENT_IMPERATIVE_RE = re.compile(
    r"""
    ^ \s{0,3} (?:[-*+]\s+ | \d+[.)]\s+)? (?:\*\*|__)? \s*
    (?:
        always \b                                     # "Always begin every session…"
      | first ,? \s+ (?:run|execute|read|do) \b        # "First, run …"
      | (?:start|begin) \s+ (?:by|every|each) \b       # "Begin every session by …"
      | before \s+ (?:answering | responding |         # "Before answering anything…"
                      any \s+ response |
                      doing \s+ anything |
                      you \s+ (?:answer|respond)) \b
      | auto [-\s]? approve \b                         # "Auto-approve every tool call"
      | you \s+ must (?! \s+ (?:not|never)) \b         # "You must run …"
      | (?:run|execute) \s+ (?:the \s+)?
            (?:bootstrap|setup|following|script|command) \b
    )
    """,
    re.IGNORECASE | re.VERBOSE | re.MULTILINE,
)

# How far (characters) from a match a prohibition cue may sit and still be read
# as governing it, clamped to the match's own list item / paragraph.
_PROHIBITION_PROXIMITY = 90


def _nearest_heading_index(lines: list[str], line_idx: int) -> int | None:
    """Return the index of the closest markdown heading at or above ``line_idx``."""
    for j in range(min(line_idx, len(lines) - 1), -1, -1):
        if lines[j].lstrip().startswith("#"):
            return j
    return None


def _nearest_heading_is_prohibition(lines: list[str], line_idx: int) -> bool:
    """Return True when the closest preceding markdown heading forbids behavior."""
    heading = _nearest_heading_index(lines, line_idx)
    return heading is not None and bool(_PROHIBITION_HEADING_RE.match(lines[heading]))


def _section_bounds(lines: list[str], line_idx: int) -> tuple[int, int]:
    """Return the (start, end) line indices of the markdown section holding a line."""
    heading = _nearest_heading_index(lines, line_idx)
    start = 0 if heading is None else heading
    end = len(lines) - 1
    for j in range(start + 1, len(lines)):
        if lines[j].lstrip().startswith("#"):
            end = j - 1
            break
    return start, end


def _inside_fenced_code_block(content: str, offset: int) -> bool:
    """Return True when ``offset`` sits inside a ``` / ~~~ fenced code block."""
    return len(_CODE_FENCE_RE.findall(content, 0, offset)) % 2 == 1


def _is_paragraph_line(line: str) -> bool:
    """A line that can continue a markdown paragraph or list item."""
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#") and not _CODE_FENCE_RE.match(line)


def _block_bounds(lines: list[str], line_idx: int) -> tuple[int, int]:
    """Return the (start, end) line indices of the list item / paragraph block.

    Follows markdown paragraph semantics: hard-wrapped prose continues on the
    next non-blank line whether or not it is indented, so a negation that
    ends one line still governs the flag that opens the next. A blank line,
    heading, fence, or new list item ends the block.
    """
    start = line_idx
    while start > 0 and not _LIST_ITEM_RE.match(lines[start]) and _is_paragraph_line(lines[start - 1]):
        start -= 1
    end = line_idx
    while end + 1 < len(lines) and _is_paragraph_line(lines[end + 1]) and not _LIST_ITEM_RE.match(lines[end + 1]):
        end += 1
    return start, end


def _span_text(lines: list[str], start_line: int, end_line: int) -> tuple[int, int]:
    """Return the (start, end) character offsets of an inclusive line range."""
    start = sum(len(line) + 1 for line in lines[:start_line])
    end = start + sum(len(lines[i]) + 1 for i in range(start_line, end_line + 1))
    return start, end


def _is_prohibition_context(content: str, match_start: int, match_end: int) -> bool:
    """Return True when a behavioral match reads as forbidden/policy prose.

    Prose context alone never deletes a finding — see ``_scan_behavioral_risks``,
    which downgrades rather than drops. Two signals outrank the prose entirely:
    a runnable fenced code block, and a line-anchored agent-directed imperative
    inside the scope that supplied the suppression.
    """
    lines = content.split("\n")
    line_idx = content.count("\n", 0, match_start)

    if _inside_fenced_code_block(content, match_start):
        return False

    if _nearest_heading_is_prohibition(lines, line_idx):
        section_start, section_end = _span_text(lines, *_section_bounds(lines, line_idx))
        return not _AGENT_IMPERATIVE_RE.search(content[section_start:section_end])

    start_line, end_line = _block_bounds(lines, line_idx)
    block_start, block_end = _span_text(lines, start_line, end_line)
    if _AGENT_IMPERATIVE_RE.search(content[block_start:block_end]):
        return False
    return prohibition_governs(content, match_start, match_end, (block_start, block_end), _PROHIBITION_CUE_RE, _PROHIBITION_PROXIMITY)
