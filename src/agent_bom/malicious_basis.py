"""What a package's malicious flag rests on, and how each surface words it.

``is_malicious`` is the blocking flag every gate reads, so it covers guesses as
well as facts. A name-similarity or dependency-confusion match stays blocked,
but it is only ever worded as suspected. The basis is read from
``malicious_reason`` so reports stored before the field existed read correctly.
"""

from __future__ import annotations

NAME_SIMILARITY = "name_similarity"
DEPENDENCY_CONFUSION = "dependency_confusion"
KNOWN_MALICIOUS = "known_malicious"
UNSPECIFIED = "unspecified"

MALICIOUS_VERDICT = "malicious"
SUSPECTED_VERDICT = "suspected_malicious"
BLOCKING_VERDICTS = frozenset({MALICIOUS_VERDICT, SUSPECTED_VERDICT})

_REASON_PREFIXES = {
    "Possible typosquat": NAME_SIMILARITY,
    "Dependency confusion": DEPENDENCY_CONFUSION,
}
_SUSPECTED_BASES = frozenset(_REASON_PREFIXES.values())
_BASIS_WORDING = {
    NAME_SIMILARITY: "name similarity",
    DEPENDENCY_CONFUSION: "an internal-looking name",
}


def malicious_basis(reason: str | None) -> str:
    """The kind of evidence behind ``reason``."""
    text = (reason or "").strip()
    if not text:
        return UNSPECIFIED
    return next((basis for prefix, basis in _REASON_PREFIXES.items() if text.startswith(prefix)), KNOWN_MALICIOUS)


def is_suspected(reason: str | None) -> bool:
    return malicious_basis(reason) in _SUSPECTED_BASES


def malicious_verdict_value(reason: str | None) -> str:
    return SUSPECTED_VERDICT if is_suspected(reason) else MALICIOUS_VERDICT


def malicious_label(reason: str | None) -> str:
    """``malicious`` or ``suspected malicious``, for use inside a sentence."""
    return "suspected malicious" if is_suspected(reason) else "malicious"


def malicious_headline(reason: str | None) -> str:
    return "SUSPECTED MALICIOUS" if is_suspected(reason) else "MALICIOUS"


def malicious_message(subject: str, reason: str | None) -> str:
    """The full verdict sentence: the fact for known malware, the basis and next step for a guess."""
    text = reason or "flagged as malicious by package intelligence"
    if not is_suspected(reason):
        return f"MALICIOUS package {subject} — {text}. Do not install."
    basis = _BASIS_WORDING[malicious_basis(reason)]
    return (
        f"SUSPECTED MALICIOUS package {subject} — {text.rstrip('.')}. "
        f"Flagged on {basis} only; no advisory reports it as malicious. "
        "Confirm the name and publisher on the registry before installing."
    )


def package_basis_fields(row_reason: str | None, flagged: bool) -> dict[str, str]:
    """The optional ``malicious_basis`` key for a serialized row; absent on an unflagged package."""
    return {"malicious_basis": malicious_basis(row_reason)} if flagged else {}
