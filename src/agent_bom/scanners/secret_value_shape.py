"""Whether a secret-named assignment holds a value, and where a match sits on its line.

Secret rules key on a name (``api_key =``, ``password:``). The name says nothing
about the right-hand side, which may be code reading a value, or a translated
label for a password field. Each judgement here looks at that right-hand side
and defaults to "keep the finding" when it cannot tell.
"""

from __future__ import annotations

import re
import sys
from bisect import bisect_right
from collections.abc import Callable
from pathlib import PurePath

_ASSIGNED_NAME_RE = re.compile(r"[^=:\n]{0,64}[=:]\s*(?:await\s+|new\s+)?([A-Za-z_$][\w$.]{0,200})")
# Letters with at most a short version suffix, per segment. A random token carries
# digits inside its segments, which is what keeps it out of this shape.
_IDENTIFIER_CHAIN_RE = re.compile(r"_*[A-Za-z]+\d{0,2}(?:[._]+[A-Za-z]+\d{0,2})*_*")
_REFERENCE_PREFIXES = ("self.", "this.", "cls.", "process.env.", "import.meta.env.", "os.environ", "system.getenv")
_NAMED_AFTER_SECRET_RE = re.compile(r"(?i)^[a-z_$][\w$.]*(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|password|secret)$")
_AFTER_BARE_NAME = frozenset(" \t,;)}]#/`")


def _inside_string_literal(line: str, position: int, *, code_file: bool) -> bool:
    """A value quoted earlier on the line is text, however much it looks like a name.

    A backtick opens a string only in code; in Markdown it marks a code span.
    """
    openers = "'\"`" if code_file else "'\""
    quote = ""
    index = 0
    while index < position:
        char = line[index]
        if char == "\\":
            index += 2
            continue
        if quote:
            quote = "" if char == quote else quote
        elif char in openers:
            quote = char
        index += 1
    return bool(quote)


def assigned_from_code(line: str, match: re.Match, *, code_file: bool) -> bool:
    """Whether a matched assignment takes its value from a call, attribute or variable.

    A call, a subscript, a well-known lookup and a name that itself ends in the
    secret word read the same in any file. A plain bare word is an identifier
    only in a language where string values must be quoted.
    """
    assigned = _ASSIGNED_NAME_RE.match(line, match.start())
    if assigned is None or _inside_string_literal(line, assigned.start(1), code_file=code_file):
        return False
    name = assigned.group(1)
    rest = line[assigned.end() :]
    if rest.lstrip()[:1] in {"(", "["}:
        return True
    if rest[:1] and rest[0] not in _AFTER_BARE_NAME:
        return False
    if name.lower().startswith(_REFERENCE_PREFIXES) or _NAMED_AFTER_SECRET_RE.fullmatch(name):
        return True
    return code_file and _IDENTIFIER_CHAIN_RE.fullmatch(name) is not None


_TRANSLATION_DIRS = frozenset({"i18n", "l10n", "locale", "locales", "lang", "translation", "translations"})
_TRANSLATION_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".toml", ".properties"})
_LABEL_KEY_RE = re.compile(
    r"(?i)^(?:label|lbl|msg|message|title|placeholder|hint|help|text|txt|error|err|tooltip|caption|mandatory|invalid)_"
)
_QUOTED_VALUE_RE = re.compile(r"""[=:]\s*(["'])((?:(?!\1)[^\\\n]|\\.){0,2048})\1""")
_WORDS_ONLY_RE = re.compile(r"[^\W\d_]+(?:[-'’][^\W\d_]+)*")
_NAMES_THE_FIELD_RE = re.compile(r"(?i)\b(?:password|passwd|secret)\b")


def is_translation_file(rel_path: str) -> bool:
    """A structured file under a directory conventionally holding UI translations."""
    path = PurePath(rel_path)
    return path.suffix.lower() in _TRANSLATION_SUFFIXES and any(part.lower() in _TRANSLATION_DIRS for part in path.parts[:-1])


def _reads_as_label(value: str) -> bool:
    if any(char.isspace() for char in value):
        return True
    return any(ord(char) > 127 and char.isalpha() for char in value) or _WORDS_ONLY_RE.fullmatch(value) is not None


def is_label_assignment(line: str, match: re.Match, *, translation_file: bool) -> bool:
    """Whether a password/secret-named string is UI text rather than a credential.

    In a translation file any value that reads as words is a label; a value with
    digits or symbols and no spaces still reports. Elsewhere a value must contain
    spaces and also be under a label-style key or name the field it describes,
    so a spaced passphrase under a plain ``password`` key still reports.
    """
    # The rule stops at the first quote of either kind, so read on to the closing
    # quote of the same kind: an apostrophe does not end a double-quoted label.
    quoted = _QUOTED_VALUE_RE.search(line, match.start())
    if quoted is None:
        return False
    value = quoted.group(2)
    if translation_file:
        return _reads_as_label(value)
    if not any(char.isspace() for char in value):
        return False
    key_start = match.start()
    while key_start > 0 and (line[key_start - 1].isalnum() or line[key_start - 1] == "_"):
        key_start -= 1
    return _LABEL_KEY_RE.match(line[key_start : match.start()]) is not None or _NAMES_THE_FIELD_RE.search(value) is not None


# A request URL or a path to a static asset names a resource. Digits in it are
# identifiers, whatever personal-data format they happen to resemble.
_URL_BODY_RE = re.compile(r"://[^\s'\"<>`]{1,4096}")
_URL_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")
_ASSET_SUFFIX_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|bmp|avif|mp4|webm|mp3|wav|ogg|pdf|woff2?|ttf|eot|otf|css|js|mjs|map)(?![\w-])",
    re.IGNORECASE,
)
_ASSET_PATH_PUNCTUATION = frozenset("%.~@+/-_")
_MAX_SCHEME_CHARS = 24
_MAX_ASSET_PATH_CHARS = 512
_PERSONAL_QUERY_PARAM_RE = re.compile(r"(?i)[?&;](?:ssn|social|phone|mobile|tel|card|email|mail|dob|iban|passport|mrn)[\w-]{0,32}=[^&;]*$")


def _walk_back(line: str, position: int, limit: int, accepts: Callable[[str], bool]) -> int:
    floor = max(0, position - limit)
    while position > floor and accepts(line[position - 1]):
        position -= 1
    return position


class LineLocators:
    """The URLs and asset paths of one line, found once however many matches it holds.

    Finding the fixed part first and walking back keeps this linear on long lines
    such as minified JSON, where a pattern anchored on the path would not be.
    """

    def __init__(self, line: str) -> None:
        self._line = line
        self._urls = [
            (_walk_back(line, url.start(), _MAX_SCHEME_CHARS, _URL_SCHEME_CHARS.__contains__), url.end())
            for url in _URL_BODY_RE.finditer(line)
        ]
        self._assets = [
            (
                _walk_back(line, asset.start(), _MAX_ASSET_PATH_CHARS, lambda char: char.isalnum() or char in _ASSET_PATH_PUNCTUATION),
                asset.end(),
            )
            for asset in _ASSET_SUFFIX_RE.finditer(line)
        ]

    @staticmethod
    def _covering(spans: list[tuple[int, int]], start: int, end: int) -> tuple[int, int] | None:
        index = bisect_right(spans, (start, sys.maxsize)) - 1
        return spans[index] if index >= 0 and spans[index][0] <= start and end <= spans[index][1] else None

    def contains(self, start: int, end: int) -> bool:
        """Whether a span sits in a URL or asset path, not in a parameter naming personal data."""
        url = self._covering(self._urls, start, end)
        if url is not None:
            return _PERSONAL_QUERY_PARAM_RE.search(self._line, url[0], start) is None
        return self._covering(self._assets, start, end) is not None
