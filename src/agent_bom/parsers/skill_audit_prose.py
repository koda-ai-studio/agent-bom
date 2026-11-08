"""Decide whether a prohibition cue or a report frame governs a behavioral match.

A cue only governs a match in the same sentence: before it ("Never run X")
or after it as an approval gate or predicate ("X only after review",
"X is not allowed"). A fresh imperative clause ("X and do not tell the
user"), a cue in a neighbouring sentence, a negated refusal ("Do not hesitate
to X") or a cue on another clause ("Do not tell them, just X") is the author's
own wording around a directive, not a prohibition of it.

A quote alone proves nothing, because the author chooses it. A quoted match is
a labelled example only when all of this holds in its sentence: the sentence
opens by reporting on text, a link ties that text to the quote, the quote holds
exactly the match, nothing tells the agent to act on it, and whatever follows
the quote is more examples or more reporting. Any doubt leaves the match a
directive; the result only ever lowers severity, and the evidence stays visible.
"""

from __future__ import annotations

import re

_SENTENCE_END_RE = re.compile(r"(?<!e\.g)(?<!i\.e)[.!?][\"'”’`]?(?=\s|$)")

_TRAILING_CUE_RE = re.compile(
    r"\b(?:without\s+(?:(?:an?|prior|explicit|the)\s+){0,4}(?:explicit|prior|human|user|written|manual)|"
    r"(?:require[sd]?|need(?:s|ed)?|after|only\s+after|upon|following|pending|once)"
    r"\s+(?:(?:an?|explicit|prior|human|user|manual|written|the)\s+){0,4}"
    r"(?:review|approval|confirmation|consent|sign[-\s]?off|request)|"
    r"(?:is|are|be|was|were)\s+(?:not\s+(?:allowed|permitted)|never\s+allowed|forbidden|prohibited|disallowed|banned|blocked))\b",
    re.IGNORECASE,
)

# A negated refusal is an order: "Do not hesitate to ...", "Never refuse ...", "Never skip this step: ...".
_COUNTER_VERB_RE = re.compile(
    r"\s*(?:ever\s+)?(?:(?:hesitat|refus|fail|forget|stop|question|resist|delay|doubt|declin|object|wait|paus)\w*\b"
    r"|(?:skip|omit|neglect)\w*(?:\s+\w+){0,3}\s*:)",
    re.IGNORECASE,
)
_CLAUSE_BREAK_RE = re.compile(r";|\s[—–]\s|,\s*(?:just|instead|simply|rather|then|but)\b", re.IGNORECASE)

# Past this a sentence is not prose anyone wrote to report a phrase, and each match would rescan it.
_MAX_EXAMPLE_SENTENCE = 2000
_OPENING_QUOTES = "\"'`“‘"
_QUOTE_CLOSE_RE = re.compile(r"[.,!?]?[\"'`”’]")
_QUOTED_RE = re.compile(r"\"[^\"]*\"|`[^`]*`|“[^”]*”|‘[^’]*’|(?<!\w)'[^']*'(?!\w)")
_LINE_PREFIX_RE = re.compile(r"\s*(?:>\s*)*(?:[-*+]\s+|\d+[.)]\s+)?(?:\*\*|__)?\s*(?:description:\s*[\"']?)?", re.IGNORECASE)

# What a sentence must open with to be about text rather than addressed to the agent.
_REPORT_LEAD_RE = re.compile(
    r"(?:(?:also|then|please)\s+)?(?:report(?:s|ing)?|flag(?:s|ging)?|detect(?:s|ing)?|catch(?:es)?|blocks?|rejects?|"
    r"looks?\s+for|watch(?:es)?\s+for|scans?\s+for|search(?:es)?\s+for|checks?\s+for|finds?|identif(?:y|ies)|highlights?|lists?)\b"
    r"|(?:(?:any|all|the|such)\s+)?(?:phrases?|wording|text|strings?|messages?|prompts?|instructions?|comments?|content|lines?|inputs?|"
    r"requests?|attempts?|commands?|flags?|patterns?|examples?)\b"
    r"|(?:if|when|whenever)\b[^,]*\b(?:contains?|includes?|mentions?|says?|asks?|tells?)\b",
    re.IGNORECASE,
)
_CONDITIONAL_RE = re.compile(r"(?:if|when|whenever)\b", re.IGNORECASE)
# What must tie that text to the quote.
_EXAMPLE_LINK_RE = re.compile(
    r"\b(?:such\s+as|e\.g\.|for\s+example|for\s+instance|like|phrases?|"
    r"(?:that|which)\s+(?:asks?|tells?|instructs?|urges?|tries|attempts?|says?|claims?|contains?|includes?)|"
    r"asking|telling|instructing|urging|containing|including|saying)(?=\W|$)",
    re.IGNORECASE,
)
_ACT_ON_RE = re.compile(
    r"\b(?:(?<!the\s)follow(?:s|ed|ing)?|obey(?:s|ed|ing)?|compl(?:y|ies|ied|ying)|heed(?:s|ed|ing)?|honou?r(?:s|ed|ing)?|"
    r"execut(?:e|es|ed|ing)|appl(?:y|ies|ied|ying)|adopt(?:s|ed|ing)?|perform(?:s|ed|ing)?|implement(?:s|ed|ing)?|"
    r"accept(?:s|ed|ing)?|respect(?:s|ed|ing)?|trust(?:s|ed|ing)?|prioriti[sz](?:e|es|ed|ing)|listen(?:s|ed|ing)?\s+to|"
    r"carr(?:y|ies|ied|ying)\s+out|act(?:s|ed|ing)?\s+on|must\s+be|binding|take\s+priority)\b"
    r"|(?:^|[,:]\s*|\b(?:and|then|please|must|should)\s+)"
    r"(?:use|say|repeat|output|print|write|insert|add|append|inject|send|include|respond|reply|answer|run|do\s+(?:it|this|that|so|as))\b",
    re.IGNORECASE,
)
_NEGATED_RE = re.compile(r"(?:\bnot|\bnever|n't|\bwithout)\s+(?:\w+\s+)?$", re.IGNORECASE)
_ONLY_CONNECTORS_RE = re.compile(r"(?:\s|[,.!?:()*_/]|\b(?:and|or|etc)\b)*", re.IGNORECASE)
_REPORTING_WORD_RE = re.compile(
    r"\b(?:report|flag|injection|finding|attack|untrusted|suspicious|malicious|coercion|risk|danger|unsafe|remote|execution|exfiltrat)",
    re.IGNORECASE,
)
_CLAUSE_JOIN_RE = re.compile(r"\b(?:and|then)\b", re.IGNORECASE)
_ADDRESSES_AGENT_RE = re.compile(
    r"\b(?:you|agent|model|assistant)\s+(?:should|must|shall|will|can|may)\b(?!\s+(?:not|never)\b)", re.IGNORECASE
)
_NEGATED_CLAUSE_RE = re.compile(r"\s*(?:do\s+not|don't|never|must\s+not|should\s+not)\b", re.IGNORECASE)


def _tells_agent_to_act(prose: str) -> bool:
    return any(not _NEGATED_RE.search(prose[: found.start()]) for found in _ACT_ON_RE.finditer(prose))


def _only_reports_after_quote(after: str) -> bool:
    """Whatever follows the quote is more examples, or clauses that report or refuse."""
    if _ONLY_CONNECTORS_RE.fullmatch(after):
        return True
    if _ADDRESSES_AGENT_RE.search(after):
        return False
    clauses = [clause for clause in _CLAUSE_JOIN_RE.split(after) if not _ONLY_CONNECTORS_RE.fullmatch(clause)]
    return all(_REPORTING_WORD_RE.search(clause) or _NEGATED_CLAUSE_RE.match(clause) for clause in clauses)


def _conditional_stays_on_the_example(before: str) -> bool:
    """In "If X contains Y, such as ...", no other clause may follow the condition."""
    if not _CONDITIONAL_RE.match(before) or "," not in before:
        return True
    tail = before.rsplit(",", 1)[1].strip()
    return not tail or bool(_EXAMPLE_LINK_RE.match(tail))


def sentence_acts_on_match(content: str, match_start: int, match_end: int, block: tuple[int, int]) -> bool:
    """True when the match's own sentence tells the agent to act, whatever heading sits above it."""
    start, end = _sentence_bounds(content, match_start, match_end, *block)
    prose = f"{content[start:match_start]} {content[match_end:end]}"
    return _tells_agent_to_act(_QUOTED_RE.sub(" ", prose).strip(" \"'`\u201c\u201d\u2018\u2019"))


def _is_labelled_example(content: str, match_start: int, match_end: int, sentence_start: int, sentence_end: int) -> bool:
    """A quoted match in a sentence that reports on it and never tells the agent to act on it."""
    closing = _QUOTE_CLOSE_RE.match(content, match_end)
    if (
        sentence_end - sentence_start > _MAX_EXAMPLE_SENTENCE
        or match_start == 0
        or content[match_start - 1] not in _OPENING_QUOTES
        or closing is None
    ):
        return False
    lead = content[sentence_start : match_start - 1]
    lead = lead[_LINE_PREFIX_RE.match(lead).end() :]  # type: ignore[union-attr]
    if not _REPORT_LEAD_RE.match(lead) or not _EXAMPLE_LINK_RE.search(lead):
        return False
    before = _QUOTED_RE.sub(" ", lead)
    after = _QUOTED_RE.sub(" ", content[closing.end() : sentence_end])
    if any(_CLAUSE_BREAK_RE.search(part) or _tells_agent_to_act(part.strip()) for part in (before, after)):
        return False
    return _conditional_stays_on_the_example(before) and _only_reports_after_quote(after)


def _cue_governs(before: str, cue: re.Pattern[str]) -> bool:
    negated_until = 0
    for found in cue.finditer(before):
        if found.start() < negated_until:
            continue
        counter = _COUNTER_VERB_RE.match(before, found.end())
        if counter is not None:
            negated_until = counter.end()
            continue
        if not _CLAUSE_BREAK_RE.search(before, found.end()):
            return True
    return False


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
    """Return True when a prohibition cue or report frame in the match's sentence governs it."""
    sentence_start, sentence_end = _sentence_bounds(content, match_start, match_end, *block)
    if _is_labelled_example(content, match_start, match_end, sentence_start, sentence_end):
        return True
    before = content[max(sentence_start, match_start - proximity) : match_start]
    after = content[match_end : min(sentence_end, match_end + proximity)]
    return _cue_governs(before, cue) or bool(_TRAILING_CUE_RE.search(after))
