"""The redactor and the secret scanner must judge entropy with one implementation."""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom import secret_scanner, security
from agent_bom.redaction.entropy import shannon_entropy

SRC = Path(__file__).resolve().parent.parent / "src" / "agent_bom"


def test_one_shannon_entropy_definition_in_the_package() -> None:
    owners = [
        path.relative_to(SRC).as_posix()
        for path in SRC.rglob("*.py")
        if re.search(r"^\s*def _?shannon_entropy\(", path.read_text(encoding="utf-8"), re.MULTILINE)
    ]
    assert owners == ["redaction/entropy.py"]


def test_callers_use_the_shared_implementation() -> None:
    assert security._shannon_entropy is shannon_entropy
    assert secret_scanner._shannon_entropy is shannon_entropy
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert round(shannon_entropy("abcd"), 6) == 2.0
